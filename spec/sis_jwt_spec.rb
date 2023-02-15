# frozen_string_literal: true
module Sisjwt
  RSpec.describe SisJwt do
    describe "#build" do
      it "uses SisJwtOptions.current" do
        options = {}
        expect(SisJwtOptions).to receive(:current).and_return(options)
        expect(SisJwt).to receive(:new).with(options).and_call_original

        jwt = SisJwt.build

        expect(jwt.options).to be options
      end
    end

    describe ".initialize" do
      it "assigns options and logger" do
        options = SisJwtOptions.current
        logger = Logger.new("/dev/null")

        jwt = SisJwt.new(options, logger: logger)

        expect(jwt.options).to be options
        expect(jwt.logger).to be logger
      end
    end

    describe ".encode" do
      let(:payload) { { a:1 } }
      let(:jwt_secret) { a_kind_of(String) }
      let(:jwt_algo) { a_kind_of(Algo::SisJwtV1) }
      let(:pseudo_token) { "LOLIMAJWT" }
      let(:options) { o=SisJwtOptions.current; o.token_type = TOKEN_TYPE_DEV; o }
      subject { SisJwt.new(options) }

      it do
        expect(options.kms_configured?).to be_falsy
        expect(options).to be_valid
      end

      it "requires that payload is a hash" do
        ret = nil
        expect {
          ret = subject.encode(:not_a_hash)
        }.to raise_error ArgumentError
      end

      context "payload" do
        let(:payload) do
{
            # "iss" => "PISSUER",
            # "aud" => "PAUDIENCE",
            "iat" => 12345.1,
            "exp" => 67890.2,
          }
        end
        # let(:jwt_secret) { a_kind_of(String) }
        # let(:jwt_algo) { a_kind_of(Algo::SisJwtV1) }
        let(:headers) { a_kind_of(Hash) }
        # let(:pseudo_token) { "LOLIMAJWT" }

        before do
          # expect(::JWT).to receive(:encode).with(payload, jwt_secret, jwt_algo, headers).and_return(pseudo_token)

          # ret_token = subject.encode(payload)
          # expect(ret_token).to eq ret_token
        end

        context "overrides values if present" do
          it "iss" do
            expected = a_hash_including({
              "iss" => options.iss,
            })
            expect(::JWT).to receive(:encode).with(expected, jwt_secret, jwt_algo, headers).and_return(pseudo_token)
            token = subject.encode(payload)
            expect(token).to eq pseudo_token
          end

          it "aud" do
            expected = a_hash_including({
              "aud" => options.aud,
            })
            expect(::JWT).to receive(:encode).with(expected, jwt_secret, jwt_algo, headers).and_return(pseudo_token)
            token = subject.encode(payload)
            expect(token).to eq pseudo_token
          end
        end

        context "uses values if present" do
          context "as numerics on payload" do
            it "iat" do
              payload["iat"] = 7.7
              expected = a_hash_including({
                "iat" => 7.7
              })
              expect(::JWT).to receive(:encode).with(expected, jwt_secret, jwt_algo, headers).and_return(pseudo_token)
              token = subject.encode(payload)
              expect(token).to eq pseudo_token
            end

            it "exp" do
              payload["exp"] = 7.7
              expected = a_hash_including({
                "exp" => 7.7
              })
              expect(::JWT).to receive(:encode).with(expected, jwt_secret, jwt_algo, headers).and_return(pseudo_token)
              token = subject.encode(payload)
              expect(token).to eq pseudo_token
            end
          end

          context "as non-numerics in payload" do
            it "iat" do
              payload["iat"] = :not_numeric
              expected = a_hash_including({
                "iat" => be_within(0.5).of(options.iat),
              })
              expect(::JWT).to receive(:encode).with(expected, jwt_secret, jwt_algo, headers).and_return(pseudo_token)
              token = subject.encode(payload)
              expect(token).to eq pseudo_token
            end

            it "exp" do
              payload["exp"] = :not_numeric
              expected = a_hash_including({
                "exp" => be_within(0.5).of(options.exp),
              })
              expect(::JWT).to receive(:encode).with(expected, jwt_secret, jwt_algo, headers).and_return(pseudo_token)
              token = subject.encode(payload)
              expect(token).to eq pseudo_token
            end
          end
        end

        it "removes nil values" do
          payload["non-empty"] = :value
          payload["empty"] = nil
          expected = a_hash_including(payload.dup)
          expect(::JWT).to_not receive(:encode).with(expected, jwt_secret, jwt_algo, headers)
          allow(::JWT).to receive(:encode).and_return(pseudo_token)
          token = subject.encode(payload)
          expect(token).to eq pseudo_token
        end
      end

    context "headers" do
      context "/w KMS" do
          let(:options) do
            SisJwtOptions.current.tap do |o|
              o.aws_region = "us-west-2"
              o.token_type = TOKEN_TYPE_V1
              o.key_alg = "KEWL_AWS_SIGNING_ALG"
              o.key_id = "arn:key"
            end
          end

          before do
            expect(options.kms_configured?).to be_truthy
          end

          it "alg / kid / AWS_ALG" do
            expected = {
              alg: TOKEN_TYPE_V1,
              kid: options.key_id,
              AWS_ALG: options.key_alg,
            }
            expect(::JWT).to receive(:encode).with(a_kind_of(Hash), jwt_secret, jwt_algo, expected).and_return(pseudo_token)
            token = subject.encode(payload)
            expect(token).to eq pseudo_token
          end
        end

        context "w/o KMS" do
          it "alg" do
            expected = a_hash_including({
              alg: TOKEN_TYPE_DEV,
            })
            expect(::JWT).to receive(:encode).with(payload, jwt_secret, jwt_algo, expected).and_return(pseudo_token)
            token = subject.encode(payload)
            expect(token).to eq pseudo_token
          end

          it "kid" do
            expected = a_hash_including({
              kid: a_kind_of(Object),
            })
            expect(::JWT).to_not receive(:encode).with(payload, jwt_secret, jwt_algo, expected)
            token = subject.encode(payload)
          end

          it "AWS_ALG" do
            expected = a_hash_including({
              AWS_ALG: a_kind_of(Object),
            })
            expect(::JWT).to_not receive(:encode).with(payload, jwt_secret, jwt_algo, expected)
            token = subject.encode(payload)
          end
        end

        it "removes null values" do
          expected = a_hash_including({
            alg: nil,
            kid: nil,
            AWS_ALG: nil,
          })
          expect(::JWT).to_not receive(:encode).with(payload, jwt_secret, jwt_algo, expected)
          token = subject.encode(payload)
        end
      end
    end

    describe ".verify" do
      # let(:token) { 'eyJhbGciOiJTSVNLTVNkIn0.eyJhY2NvdW50IjoiNjQ2QkFFMzgtRkYyNi00QjVBLThDQ0EtNUVBRTNERDk3RUU3IiwiaW52aXRlIjoiMyIsImlzcyI6InNpYyIsImF1ZCI6InNpZSIsImlhdCI6MTY3NjQxNzkzOC4yNTYyODgsImV4cCI6MTY3NjQyMTUzOH0.FsTT5isbNeZUkuvM9RQrBDBraKSFbwBVDvx6afF0bvfHxUCxPRV1Yr3WRXteRWvvEK6DwV9nh9pfPWYkR0SObw' }
      let(:key_id) { 'arn:aws:kms:us-west-2:895963939461:key/mrk-21a175a6153f41dda888d52b23f3e4c9' }
      let(:aws_alg) { 'RSASSA_PKCS1_V1_5_SHA_256' }
      let(:token) { 'eyJhbGciOiJTSVNLTVMxLjAiLCJraWQiOiJhcm46YXdzOmttczp1cy13ZXN0LTI6ODk1OTYzOTM5NDYxOmtleS9tcmstMjFhMTc1YTYxNTNmNDFkZGE4ODhkNTJiMjNmM2U0YzkiLCJBV1NfQUxHIjoiUlNBU1NBX1BLQ1MxX1YxXzVfU0hBXzI1NiJ9.eyJhY2NvdW50IjoiNjQ2QkFFMzgtRkYyNi00QjVBLThDQ0EtNUVBRTNERDk3RUU3IiwiaW52aXRlIjoiMyIsImlzcyI6InNpYyIsImF1ZCI6InNpZSIsImlhdCI6MTY3NjQyMzkyNS42MzA2NzYsImV4cCI6MTY3NjQyNzUyNX0.ED5Z1xiq64iUs-ic6UeHsEdrTnvb_ZMRYV_7TidDeusNIUXHBlPgdjeMD9qHWrzaUVte9sIKiyuPGwqngIZpmCdAiX9biZON7w3m24ukmCJnb86cCowHm-cQCuQjpQRU8ntB3ONW1dBq5zQsXUn0wHKYcm0BW86gPtf9W8ono_zUXhINsN5IzSrIna--vx0MuxKnngRdmulHR1P18xr11x4jdD-lhBgMnUB4NtL9ZZ8LqluUdV6yNXERUa4RXNMZwSfh0z_ARlOrruRnpMSp70IfdjIWzem7GIq2iF2GsGDOs6LszYMid4cgU96WSzlLGT_AH6lBKw47yfv2Vnan2lvIncK40FNo00bL4qkpAShE-i4DmiZZvWNJF4dXZIYTDxxlJMfPG8wySvpNkBagTCfmdb8p66w4jvC0WgTc9axRpVOVCLuP2Bd971W6kChVbQVZ_M37COhK1tp-sVEdmiC-0H9nol0UpY6-SXB4gwPL0qX-b9UILT0EWfcL0Z2Guu58j-VGj1u4yZZYLg7hxgph8KyAKoh1eIGLNyAxTkNQIJUQlrRGIs7isSquyHnGeuRDmNGVND5KMD8WmaKbq_bXnrUtxJKBdQPxH0vQJ_whemntYwP1wqWsie-PrZea6YYvZnAN-1FiSZeXJQRBz8eYyrH251V0wQnlAUiAUZg'}
      let(:token_data) do
        parts = token.split(".", 3)
        parts[0] + "." + parts[1]
      end
      let(:algo) { Algo::SisJwtV1.new(options) }
      let(:options) do
        SisJwtOptions.current.tap do |opts|
          opts.aws_region = "us-west-2"
          opts.token_type = TOKEN_TYPE_V1
          opts.key_id = key_id
          opts.key_alg = aws_alg
        end
      end
      subject { SisJwt.new(options) }

      it "uses JWT library to decode token"

      context "AWS KMS configured" do
        before do
          allow(options).to receive(:kms_configured?).and_return(true)
          allow(algo).to receive(:kms_verify).and_return(true)
        end

        it "returns KMS verification context" do
          allow(subject).to receive(:jwt_alg).and_return(algo)
          expect(algo).to receive(:verify) do |params|
            data = params[:data]
            _signature = params[:signature]
            verification_key = params[:verification_key]

            expect(data).to eq token_data
            expect(verification_key).to eq "#{aws_alg};#{key_id}"
          end
          subject.verify(token)
        end
      end

      context "dev mode is configured" do
        it "returns shared secret"
      end
    end
  end
end

