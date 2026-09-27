# frozen_string_literal: true

module Scute
  class Harness
    # How one tool maps to Scute: permission, object, tier.
    class ToolSpec
      attr_reader :name, :permission, :action, :resource_type, :tier

      # refund_invoice -> "invoice:refund", resetUserMfa -> "user_mfa:reset", search -> "search"
      def self.permission_for(name)
        words = name.to_s.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase.split(/[^a-z0-9]+/).reject(&:empty?)
        # A name with no letters or digits is still checked (and denied as unknown), never skipped.
        return name.to_s.empty? ? "unnamed_tool" : name.to_s if words.empty?
        return words.first if words.size < 2

        "#{words[1..].join('_')}:#{words.first}"
      end

      # config: { permission: "x:y" | false, tier:, key:, attributes: ->(args) {}, resource: ->(args) {} } or false
      # Arguments reach the engine as context.args; the object's attributes only come
      # from an explicit attributes: mapping (and Scute's stored ones win).
      def initialize(name, config, default_tier)
        config = { permission: false } if config == false
        config ||= {}
        @name = name.to_s
        @config = config
        @permission = config[:permission] == false ? nil : (config[:permission] || self.class.permission_for(name))
        @action = @permission
        @resource_type, @action = @permission.split(":", 2) if @permission&.include?(":")
        @tier = (config[:tier] || default_tier).to_sym
      end

      def resource(args)
        return @config[:resource].call(args) if @config[:resource]
        return nil unless resource_type

        key_arg = @config[:key]&.to_sym || key_candidates.find { |k| key?(args[k]) }
        resource = { type: resource_type }
        resource[:key] = args[key_arg].to_s if key_arg && key?(args[key_arg])
        attributes = @config[:attributes]&.call(args)
        resource[:attributes] = attributes if attributes && !attributes.empty?
        resource
      end

      private

      def key_candidates
        camel = resource_type.gsub(/_([a-z0-9])/) { Regexp.last_match(1).upcase }
        [:"#{resource_type}_id", :"#{camel}Id", :id]
      end

      def key?(value) = (value.is_a?(String) && !value.empty?) || (value.is_a?(Numeric) && value.finite?)
    end

    # "invoice:42", or "invoice" without a key.
    def self.resource_ref(resource)
      return "" unless resource

      resource[:key] ? "#{resource[:type]}:#{resource[:key]}" : resource[:type].to_s
    end
  end
end
