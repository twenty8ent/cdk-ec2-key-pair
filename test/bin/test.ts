#!/usr/bin/env node
import 'source-map-support/register';

import * as cdk from 'aws-cdk-lib';

import { TestStack } from '../lib/test-stack';

const app = new cdk.App();
new TestStack(app, 'EC2KeyPair', {
  env: {
        account:"081849900880",
    region: "ap-southeast-2",
  },
});
