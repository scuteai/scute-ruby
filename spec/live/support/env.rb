# frozen_string_literal: true

module ScuteLive
  # Where the live suite finds its API: SCUTE_LIVE_BASE_URL, SCUTE_LIVE_APP_ID
  # and SCUTE_LIVE_SECRET from the environment, or else from an env file
  # (SCUTE_LIVE_ENV_FILE; by default .sdk-live/ruby.env in the folder that
  # holds this checkout). The file is never part of the repo.
  module Env
    KEYS = %w[SCUTE_LIVE_BASE_URL SCUTE_LIVE_APP_ID SCUTE_LIVE_SECRET].freeze

    Config = Data.define(:base_url, :app_id, :secret) do
      def inspect = "#<ScuteLive::Env::Config #{base_url} #{app_id}>"
      alias_method :to_s, :inspect
    end

    module_function

    def file
      given = ENV.fetch("SCUTE_LIVE_ENV_FILE", "")
      given.empty? ? File.expand_path("../../../../.sdk-live/ruby.env", __dir__) : given
    end

    def values
      from_file = File.file?(file) ? parse(File.read(file)) : {}
      KEYS.to_h { |key| [key, ENV.fetch(key, "").empty? ? from_file[key].to_s : ENV.fetch(key)] }
    end

    # nil when the suite can run, otherwise why not (one line, no values).
    def missing_reason
      missing = values.select { |_, value| value.empty? }.keys
      return nil if missing.empty?

      "#{missing.join(', ')} not set (export them, or put them in #{file})"
    end

    def config
      v = values
      return nil if v.values.any?(&:empty?)

      Config.new(base_url: v["SCUTE_LIVE_BASE_URL"].sub(%r{/+\z}, ""), app_id: v["SCUTE_LIVE_APP_ID"], secret: v["SCUTE_LIVE_SECRET"])
    end

    # KEY=value lines; blank lines, comments and `export ` are fine.
    def parse(text)
      text.each_line.with_object({}) do |line, out|
        line = line.strip.delete_prefix("export ").strip
        next if line.empty? || line.start_with?("#")

        key, value = line.split("=", 2)
        next unless value

        out[key.strip] = value.strip.delete_prefix('"').delete_suffix('"').delete_prefix("'").delete_suffix("'")
      end
    end
  end
end
