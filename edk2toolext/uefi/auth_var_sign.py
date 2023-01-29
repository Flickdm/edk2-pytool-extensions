# @file
# auth_var_sign.py
#
# Command-line tool for generating and inspecting EFI_AUTHENTICATION_2 variables
# Requires "pip install edk2-pytool-extensions"
# Requires "openssl" installed for 'cryptography' lib
#
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

"""Tool for generating and inspecting EFI_AUTHENTICATION_2 variables"""

import argparse
import sys
import uuid
import os
import logging

from edk2toollib.uefi.authenticated_variables_structure_support import \
    EfiVariableAuthentication2Builder, EfiVariableAuthentication2
from edk2toollib.uefi.uefi_multi_phase import EfiVariableAttributes

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def pfx_sign(args):
    """Signs an EfiVariableAuthentication2 structure with a pkcs12.

    :param args: ArgumentParser namespace

    :return: 0 on success
    """
    # set the path for the output file
    output_file = args.data_file + ".signed"

    # Construct the EfiVariableAuthentication2 structure
    builder = EfiVariableAuthentication2Builder(args.name, args.guid, args.attributes)

    # If we have data let's update the payload with the data
    with open(args.data_file, 'rb') as f:
        builder.UpdatePayload(f)

    # grab the certificate and password for any signers passed in
    for certificate, password in args.signers_info:

        # read the entire pfx file into memory
        pkcs12_contents = b""
        with open(certificate, 'rb') as f:
            pkcs12_contents = f.read()

        top_level_certificate = None
        if args.top_level_certificate:
            with open(args.top_level_certificate, 'rb') as f:
                top_level_certificate = x509.load_der_x509_certificate(f.read())

        # load the pkcs12 (pfx) using the password associated with this pfx file
        pkcs12_store = pkcs12.load_pkcs12(pkcs12_contents, password.encode('utf-8'))

        top_level_certificate_found = False
        additional_certificates = []
        # Returns in reverse so that the first certificate is the issuer of the signer
        for cert in reversed(pkcs12_store.additional_certs):

            if top_level_certificate:

                if top_level_certificate.serial_number == cert.certificate.serial_number:
                    logger.info("Found the top level certificate")
                    top_level_certificate_found = True
                    break

            additional_certificates.append(cert)

        # if the top level certificate is provided and was not found
        if top_level_certificate and not top_level_certificate_found:
            logger.warning("Top level certificate provided was not found")

        # for each pfx file passed in, sign the payload
        builder.Sign(pkcs12_store.cert.certificate, pkcs12_store.key, additional_certificates)

    authenticated_variable = builder.Finalize()

    with open(output_file, 'wb') as f:
        authenticated_variable.Encode(f)

    logger.info("Successfully created: %s", output_file)

    return 0


def describe_variable(args):

    with open(args.signed_payload, 'rb') as f:
        authenticated_variable = EfiVariableAuthentication2(decodefs=f)

        authenticated_variable.Print()


def typecheck_file_exists(filepath):
    """Checks if this is a valid filepath for argparse.

    :param filepath: filepath to check for existance

    :return: valid filepath
    """
    if not os.path.isfile(filepath):
        raise argparse.ArgumentTypeError(
            f"You sure this is a valid filepath? : {filepath}")

    return filepath


def typecheck_pfx_file(signer):
    """Converts <certificate-path>;<password> to (certificate-path, password).

    if `sep` is missing, converts the password to ""

    :param: signer - path and password of certificate pfx file seperated by a seperator

    :return: tuple(<certificate>, <password>)
    """
    sep = ';'

    try:
        certificate_password_set = signer.split(sep, 1)

        # if the password is missing, just set the password to None
        if len(certificate_password_set) == 1:
            certificate_password_set.append("")

        if not certificate_password_set[0].lower().endswith('.pfx'):
            raise argparse.ArgumentTypeError(
                "signing certificate must be pkcs12 .pfx file")

        typecheck_file_exists(certificate_password_set[0])

        return tuple(certificate_password_set)
    except Exception as exc:
        raise ValueError(
            "signers_info must be passed as <certificate-path>{sep}<password>") from exc


def typecheck_attributes(attributes):
    """Typechecks the attributes for argparse."""
    if ',' not in attributes:
        raise argparse.ArgumentTypeError(
            "Must provide at least one of \"NV\", \"BS\" or \"RT\"")

    if 'AT' not in attributes and 'EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS' not in attributes:
        raise argparse.ArgumentTypeError(
            "The time based authenticated variable attribute (\"AT\") must be set")

    return int(EfiVariableAttributes(attributes))


def setup_signer(subparsers):
    """Sets up the signer subparser for argparse.

    :param subparsers: subparser to add arguments to

    :return: subparsers
    """
    sign_parser = subparsers.add_parser(
        "sign", help="Signs variables using the command line"
    )
    sign_parser.set_defaults(function=pfx_sign)

    sign_parser.add_argument(
        "name",
        help="UTF16 Formated Name of Variable"
    )

    sign_parser.add_argument(
        "guid", type=uuid.UUID,
        help="UUID of the namespace the variable belongs to. (Ex. 12345678-1234-1234-1234-123456789abc)"
    )

    sign_parser.add_argument(
        "attributes", type=typecheck_attributes,
        help="Variable Attributes, AT is a required (Ex \"NV,BT,RT,AT\")"
    )

    sign_parser.add_argument(
        "data_file", type=typecheck_file_exists,
        help="Binary file of variable data. An empty file is accepted and will be used to clear the authenticated data"
    )

    sign_parser.add_argument(
        "signers_info", nargs='+', type=typecheck_pfx_file,
        help="Pkcs12 certificate and password to sign the authenticated data with (<Cert.pfx>;<password>)"
    )

    sign_parser.add_argument(
        "--top-level-certificate", default=None, type=typecheck_file_exists,
        help="If included, this is the top level certificate in the pfx (pkcs12) that the signer should chain up to"
    )

    return subparsers

def setup_describe(subparsers):

    describe_parser = subparsers.add_parser(
        "describe", help="Parses Authenticated Variable 2 structures"
    )
    describe_parser.set_defaults(function=describe_variable)

    describe_parser.add_argument(
        "signed_payload", type=typecheck_file_exists,
        help="Signed payload to parse"
    )

    describe_parser.add_argument(
        "--output", default="./variable.describe",
        help="Output file to write the parse data to"
    )

    return subparsers

def parse_args():
    """Parses arguments from the command line."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser.add_argument(
        "--debug", action='store_true', default=False,
        help="enables debug printing for deep inspection"
    )

    subparsers = setup_signer(subparsers)
    subparsers = setup_describe(subparsers)

    args = parser.parse_args()

    if not hasattr(args, "function"):
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    return args


def main():
    """Main function."""
    args = parse_args()

    status_code = args.function(args)

    return sys.exit(status_code)


if __name__ == '__main__':
    main()
