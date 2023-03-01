# Sisjwt

## Usage

### `bin/sisjwt` Tool

```
$ bundle exec bin/sisjwt --help
sisjwt - Sign in Solutions JWT Generator
        --[no-]strict-mode           Turn off strict mode to allow specifying invalid values, default strict: true
        --verbose=LEVEL              Set the verbosity level, 1-5. The higher the number the more verbose
    -v                               Increase the verbosity. Can specify more than once. Default is -vvv; use --verbose if you wish to set a lower value.
    -s, --silent                     Do not output any logs or anything that is not data.  Same as --verbose=0
    -t, --type=val                   Type of Token to Generate, default SISKMSd
    -a, --alg=val                    KMS Algorithm to use to sign the token, default
    -r, --region=val                 KMS Region to use to sign the token, default us-west-2
    -e, --expires=secs               Number of seconds that the key should be valid for (used to calculate `exp` value), default 3600s
        --aud=VAL                    Token AUDience (Should be SIS company acronym: SIE, SIC, etc), default SISa
        --iss=VAL                    Token ISSuer (Should be SIS company acronym: SIE, SIC, etc), default SISi
        --exp=VAL                    Token EXPiration, unix time, default 1676415658
        --ttl=VAL                    Token Time To Live, seconds, default 3600s
```

#### Create a token

You must specify an `--iss` and `--aud`, any additional data you want in the payload you can specify in `key=value` pairs:

```
$ bundle exec bin/sisjwt --iss=sic --aud=sie sign account=646BAE38-FF26-4B5A-8CCA-5EAE3DD97EE7 invite=3
eyJhbGciOiJTSVNLTVNkIn0.eyJhY2NvdW50IjoiNjQ2QkFFMzgtRkYyNi00QjVBLThDQ0EtNUVBRTNERDk3RUU3IiwiaW52aXRlIjoiMyIsImlzcyI6InNpYyIsImF1ZCI6InNpZSIsImlhdCI6MTY3NjQxMjUyMi44Njc4NjksImV4cCI6MTY3NjQxNjEyMn0.tvXehBDdEq9Dy8CjhBhOLLmU-kV1gR3-LW7sddrE9gxXxNk1EcOGHNw4eN5A0_W9zAIvsuUahxFmUUBKHKWGsA
```

#### Verify Token

Specify the expected `--iss` and `--aud`.  You can either specify the token directly on the command line, or use `-` to indicate that it should be read from stdin.

```
$ pbpaste | bundle exec bin/sisjwt verify --iss=sic --aud=sie - | jq .
{
  "headers": {
    "alg": "SISKMSd"
  },
  "payload": {
    "account": "646BAE38-FF26-4B5A-8CCA-5EAE3DD97EE7",
    "invite": "3",
    "iss": "sic",
    "aud": "sie",
    "iat": 1676414357.660224,
    "exp": 1676417957
  },
  "allowed": {
    "aud": [
      "sie"
    ],
    "iss": [
      "sic"
    ]
  },
  "valid": true,
  "errors": {},
  "lifetime": {
    "life_left": 3594,
    "age": 6,
    "expired": false
  }
}
```

NOTE: The `lifetime` key will not be returned if running in a production environment.

## ARN Inventory

You can specify an ARN inventory that lists which KMS Key ARNs are allowed as issuers.  If an inventory file is specified then these key ARNs will be verified against the inventory and not allowed if there isn't an explicit match listed in the inventory file.

You can control which section is read using the `SISJWT_ARN_MODE` environment variable, if not specified then it will default back to `RAILS_ENV`, or `development`.


```yaml
devkube:
  sie:
    - arn:a
    - arn:b
  sic:
    - arn:c
    - arn:d
production:
  sie:
    - arn:1
    - arn:2
  sic:
    - arn:3
    - arn:4
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ErebusBat/sisjwt.
