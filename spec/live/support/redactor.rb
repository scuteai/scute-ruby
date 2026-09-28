# frozen_string_literal: true

require "delegate"

module ScuteLive
  # Nothing secret reaches the output: tokens by their shape, and every
  # secret the suite has seen (the app secret, TOTP secrets, backup codes,
  # property values, challenge tokens) by value. 424242 is not a secret.
  module Redactor
    PATTERNS = [
      [/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/, "[jwt]"],
      [/\b(?:sct|scak|scm2m)_[A-Za-z0-9_-]{8,}/, "[token]"],
      [%r{otpauth://\S+}, "[otpauth]"]
    ].freeze
    MIN_LENGTH = 8

    @secrets = []
    @lock = Mutex.new

    module_function

    def remember(*values)
      found = values.flatten.select { |v| v.is_a?(String) && v.length >= MIN_LENGTH }
      @lock.synchronize { @secrets = (@secrets | found).sort_by { |s| -s.length } }
    end

    def redact(text)
      out = PATTERNS.reduce(text.to_s) { |acc, (pattern, label)| acc.gsub(pattern, label) }
      @lock.synchronize { @secrets.dup }.reduce(out) { |acc, secret| acc.gsub(secret, "[redacted]") }
    end
  end

  # RSpec's output stream, redacted.
  class RedactingIO < SimpleDelegator
    def write(*parts) = __getobj__.write(*parts.map { |p| Redactor.redact(p) })
    def print(*parts) = __getobj__.print(*parts.map { |p| Redactor.redact(p) })
    def puts(*parts) = __getobj__.puts(*parts.flatten.map { |p| Redactor.redact(p) })

    def <<(part)
      write(part)
      self
    end
  end
end
