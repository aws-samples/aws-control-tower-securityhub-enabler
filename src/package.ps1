#!/usr/local/bin/pwsh
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Builds a lambda package from a single Python 3 module with pip dependencies.
# This is a modified version of the AWS packaging instructions:
# https://docs.aws.amazon.com/lambda/latest/dg/lambda-python-how-to-create-deployment-package.html#python-package-dependencies

remove-item -path .package,securityhub_enabler.zip -recurse -force *>$NULL
new-item -path . -Name .package -ItemType "directory" >$NULL
pip3 install --target .package --requirement requirements.txt
pushd .package >$NULL
compress-archive -Path .\* -DestinationPath ..\securityhub_enabler.zip
popd >$NULL
compress-archive -Path securityhub_enabler.py -Update -DestinationPath securityhub_enabler.zip
