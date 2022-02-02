"""
A SATOSA response microservice that implements a SAML service provider
to send an authentication request and then later receive a SAML assertion
from the stepup IdP service.

Based on an initial implementation from Ivan Kanakarakis for the eduTEAMs
project.
"""

import functools
import json
import logging
from typing import Iterable
from typing import Mapping
from urllib.parse import urlparse

from saml2 import BINDING_HTTP_POST
import saml2.xmldsig as ds
from saml2.authn_context import requested_authn_context
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.saml import NameID
from saml2.saml import Subject


import satosa.util as util
from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Response
from satosa.saml_util import make_saml_response


logger = logging.getLogger(__name__)


def is_authn_context_requirements_satisfied(accepted, received):
    satisfied = received in accepted
    return satisfied


class StepUpError(SATOSAError):
    """Generic error for this plugin."""


class StepUp(ResponseMicroService):
    """
    Configuration:
    - sigalg: the algorithm that will be used for signing the
      SAML authentication request sent to the step up IdP

      default: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256

    - digest_alg: the algorithm that will be used for digesting the SAML
      authentication request sent to the step up IdP

      default: http://www.w3.org/2001/04/xmlenc#sha256

    - nameid_from_attribute: the SATOSA internal attribute used to obtain the
      value to include for the NameID in the SAML authentication request sent
      to the step up IdP

      default: None, must be configured

    - sp_authn_context_mapping: a mapping between target SP entityIDs and
      accepted/requested SAML authentication context class values. For each SP
      there are two mappings of authentication context class values:

      (1) accepted_authn_context: the list of authentication context class
          values accepted, either from the authenticating IdP or the step up
          IdP, to reach the target SP

      (2) the requested authentication context class in the request sent to the
          step up IdP

      default: None, must be configured

    - sp_config: the configuration for the SP passed to the pysaml2 module

      default: None, must be configured
    """

    REQUESTED = "requested_authn_context"
    ACCEPTED = "accepted_authn_context"

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Validate the configuration.
        sp_mapping = config.get("sp_authn_context_mapping", {})

        is_a_mapping = isinstance(sp_mapping, Mapping)

        at_least_one = is_a_mapping and len(sp_mapping)

        entityid_is_string = is_a_mapping and all(
            type(entityid) is str for entityid in sp_mapping.keys()
        )

        auth_context_is_a_mapping = is_a_mapping and all(
            isinstance(auth_context_settings, Mapping)
            for entityid, auth_context_settings in sp_mapping.items()
        )

        auth_context_has_requested = auth_context_is_a_mapping and all(
            self.REQUESTED in auth_context.keys() and
            type(auth_context[self.REQUESTED]) is str
            for entityid, auth_context in sp_mapping.items()
        )

        auth_context_has_accepted = auth_context_is_a_mapping and all(
            self.ACCEPTED in auth_context.keys()
            and isinstance(auth_context[self.ACCEPTED], Iterable)
            and all(type(c) is str for c in auth_context[self.ACCEPTED])
            for entityid, auth_context in sp_mapping.items()
        )

        auth_context_requested_is_included_in_accepted = (
            auth_context_has_accepted
            and auth_context_has_requested
            and all(
                auth_context[self.REQUESTED] in auth_context[self.ACCEPTED]
                for entityid, auth_context in sp_mapping.items()
            )
        )

        nameid_from_attribute_is_a_string = (
            type(config.get("nameid_from_attribute")) is str
        )

        sigalg_is_a_string = type(config.get("sigalg", "")) is str
        digest_alg_is_a_string = type(config.get("digest_alg", "")) is str

        validator_keys = [
            "sp_authn_context_mapping is a mapping",
            "sp_authn_context_mapping has at least one entry",
            "each entityID is a string",
            "each entityID value is a mapping",
            "accepted_authn_context is present",
            "requested_authn_context is present",
            "requested is included in accepted",
            "nameid_from_attribute is a string",
            "sigalg is a string",
            "digest_alg is a string"
        ]

        validator_values = [
            is_a_mapping,
            at_least_one,
            entityid_is_string,
            auth_context_is_a_mapping,
            auth_context_has_accepted,
            auth_context_has_accepted,
            auth_context_requested_is_included_in_accepted,
            nameid_from_attribute_is_a_string,
            sigalg_is_a_string,
            digest_alg_is_a_string
        ]

        validators = dict(zip(validator_keys, validator_values))

        if not all(validators.values()):
            error_context = {
                "message": (
                    "The configuration for this plugin is not valid. "
                    "Make sure that the following rules are met: "
                    ", ".join(rule for rule in validators.keys())
                ),
                "validators": validators,
            }
            raise StepUpError(error_context)

        self.sp_mapping = sp_mapping
        self.sigalg = config.get("sigalg", ds.SIG_RSA_SHA256)
        self.digest_alg = config.get("digest_alg", ds.DIGEST_SHA256)
        self.nameid_from_attribute = config.get("nameid_from_attribute")

        sp_config = json.loads(
            json.dumps(config["sp_config"])
            .replace("<base_url>", self.base_url)
            .replace("<name>", self.name)
        )
        sp_conf = SPConfig().load(sp_config, metadata_construction=False)
        self.sp = Saml2Client(config=sp_conf)

        logger.info("StepUp Authentication is active")

    def process(self, context, internal_response):
        user_mfa_exempt = context.get_decoration("user_mfa_exempt")
        if user_mfa_exempt:
            return super().process(context, internal_response)

        entityid = internal_response.requester
        msg = "SP requester entityID is {}".format(entityid)
        logger.debug(msg)

        authn_context_received = internal_response.auth_info.auth_class_ref
        msg = "Authenticating IdP asserted authentication context {}"
        msg = msg.format(authn_context_received)
        logger.debug(msg)

        authn_context_settings = self.sp_mapping.get(entityid)
        nameid_value = "".join(
            internal_response.attributes.get(self.nameid_from_attribute, [])
        )
        msg = "Using NameID value {}".format(nameid_value)
        logger.debug(msg)

        is_mfa_needed = (authn_context_settings and
                         not is_authn_context_requirements_satisfied(
                            authn_context_settings[self.ACCEPTED],
                            authn_context_received
                            )
                         )
        if is_mfa_needed:
            return self._send_authn_to_stepup_service(
                context,
                internal_response,
                authn_context_settings[self.REQUESTED],
                nameid_value
            )

        return super().process(context, internal_response)

    def _send_authn_to_stepup_service(
        self, context, internal_response, authn_context, nameid_value
    ):
        entityid = self.sp.metadata.identity_providers()[0]
        req_authn_context = dict(authn_context_class_ref=[authn_context], comparison="exact")
        relay_state = util.rndstr()
        sign = self.sp.config.getattr("authn_requests_signed") or bool(
            self.sp.config.key_file and self.sp.config.cert_file
        )

        name_id = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=nameid_value)
        subject = Subject(name_id=name_id)

        kwargs = {
            "sigalg": self.sigalg,
            "digest_alg": self.digest_alg,
            "subject": subject,
            "requested_authn_context": req_authn_context,
        }

        logger.debug("kwargs is {}".format(kwargs))

        try:
            binding, destination = self.sp.pick_binding(
                service="single_sign_on_service",
                descr_type="idpsso",
                entity_id=entityid,
            )
            req_id, ht_args = self.sp.prepare_for_authenticate(
                entityid=entityid,
                binding=binding,
                #response_binding=binding,
                response_binding=BINDING_HTTP_POST,
                relay_state=relay_state,
                sign=sign,
                **kwargs
            )
        except Exception as e:
            error_context = {
                "message": "Failed to construct the AuthnRequest",
                "entityid": entityid,
                "name_id": name_id,
                "params": kwargs,
                "sign": sign,
            }
            raise StepUpError(error_context) from e

        context.state[self.name] = {
            "relay_state": relay_state,
            "internal_data": internal_response.to_dict(),
        }
        return make_saml_response(binding, ht_args)

    def _handle_authn_response(self, context, binding):
        internal_data = context.state[self.name]["internal_data"]
        internal_response = InternalData.from_dict(internal_data)
        entityid = internal_response.requester
        authn_context_settings = self.sp_mapping[entityid]

        try:
            authn_response = self.sp.parse_authn_request_response(
                context.request["SAMLResponse"], binding
            )
        except Exception as e:
            error_context = {
                "message": "Invalid AuthnResponse",
                "entityid": entityid,
                "request": context.request.get("SAMLResponse"),
                "context": context,
            }
            raise StepUpError(error_context) from e

        authn_info = authn_response.authn_info()[0]
        auth_class_ref = authn_info[0]
        authn_context_received = auth_class_ref

        is_mfa_satisfied = is_authn_context_requirements_satisfied(
            authn_context_settings[self.ACCEPTED], authn_context_received
        )
        if not is_mfa_satisfied:
            error_context = {
                "message": "Second factor authentication failed",
                "entityid": entityid,
                "config": authn_context_settings,
                "received authn context": authn_context_received,
            }
            raise StepUpError(error_context)

        internal_response.auth_info.auth_class_ref = authn_context_received
        del context.state[self.name]
        return super().process(context, internal_response)

    def _metadata_endpoint(self, context):
        metadata_string = create_metadata_string(
            None, self.sp.config, 4, None, None, None, None, None
        ).decode("utf-8")
        return Response(metadata_string, content="text/xml")

    def register_endpoints(self):
        url_map = []

        # acs endpoints
        sp_endpoints = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            parsed_endp = urlparse(endp)
            url_map.append(
                (
                    "^{endpoint}$".format(endpoint=parsed_endp.path[1:]),
                    functools.partial(self._handle_authn_response,
                                      binding=binding),
                )
            )

        # metadata endpoint
        parsed_entity_id = urlparse(self.sp.config.entityid)
        url_map.append(
            (
                "^{endpoint}".format(endpoint=parsed_entity_id.path[1:]),
                self._metadata_endpoint,
            )
        )

        return url_map
