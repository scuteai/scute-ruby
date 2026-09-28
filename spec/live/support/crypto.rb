# frozen_string_literal: true

require "json"
require "openssl"

module ScuteLive
  # What a test needs to check Scute's signatures and to act as an
  # authenticator app: JWS (RS256) against a JWKS, and TOTP codes.
  module Crypto
    BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    module_function

    # base64url without padding (pack, not the base64 gem: Ruby 3.4 no longer ships it by default).
    def b64(bytes) = [bytes].pack("m0").tr("+/", "-_").delete("=")

    def unb64(text)
      plain = text.to_s.tr("-_", "+/")
      (plain + ("=" * ((4 - (plain.length % 4)) % 4))).unpack1("m0")
    end

    # The claims of a compact JWS, without checking it.
    def claims(jws) = JSON.parse(unb64(jws.to_s.split(".")[1]))

    # The claims when the JWS verifies with a key of the JWKS (by kid), else nil.
    def verify_rs256(jws, jwks)
      header, payload, signature = jws.to_s.split(".")
      head = JSON.parse(unb64(header))
      return nil unless head["alg"] == "RS256"

      key = Array(jwks["keys"]).find { |k| k["kty"] == "RSA" && (head["kid"].nil? || k["kid"] == head["kid"]) }
      return nil unless key && rsa_key(key).verify("SHA256", unb64(signature), "#{header}.#{payload}")

      JSON.parse(unb64(payload))
    end

    def rsa_key(jwk)
      n = OpenSSL::BN.new(unb64(jwk["n"]), 2)
      e = OpenSSL::BN.new(unb64(jwk["e"]), 2)
      rsa = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e)])
      algorithm = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("rsaEncryption"), OpenSSL::ASN1::Null(nil)])
      OpenSSL::PKey::RSA.new(OpenSSL::ASN1::Sequence([algorithm, OpenSSL::ASN1::BitString(rsa.to_der)]).to_der)
    end

    # RFC 6238 (HMAC-SHA1, 30 seconds, 6 digits), what an authenticator app shows.
    def totp(secret, at: Time.now)
      mac = OpenSSL::HMAC.digest("SHA1", base32(secret), [at.to_i / 30].pack("Q>"))
      offset = mac.getbyte(-1) & 0x0f
      ((mac.byteslice(offset, 4).unpack1("N") & 0x7fffffff) % 1_000_000).to_s.rjust(6, "0")
    end

    # RFC 4648 base32, as TOTP secrets are written.
    def base32(text)
      bits = text.to_s.upcase.delete("= ").each_char.map { |c| BASE32.index(c).to_s(2).rjust(5, "0") }.join
      [bits[0, bits.length - (bits.length % 8)]].pack("B*")
    end
  end
end
