# frozen_string_literal: true

module Scute
  class Error < StandardError; end

  # Scute answered with an error (4xx/5xx). `code` is the API's error_code.
  class APIError < Error
    # body: the API's answer, when it sent one.
    attr_reader :status, :code, :body

    def initialize(message, status: nil, code: nil, body: nil)
      super(message)
      @status = status
      @code = code
      @body = body
    end
  end

  # Scute couldn't be reached (connection refused, timeout, DNS).
  class ConnectionError < Error; end

  # Something is missing to make the call (app id, secret key, a task token).
  class ConfigurationError < Error; end
end
