# frozen_string_literal: true

require "rack/mock"
require "rack/request"

RSpec.describe Scute::ClientIP do
  let(:fake) { FakeScute.new }
  let(:options) { { app_id: "app1", secret: "sk_test", base_url: "https://scute.test", transport: fake } }
  let(:client) { Scute::Client.new(**options) }
  let(:header) { "X-Scute-Client-IP" }

  def sent_ip = fake.seen.last.headers[header]

  def start_sign_in(scute) = scute.authz.start_step_up(user_id: "user1", permission: "invoice:pay", method: "email_otp")

  describe "parse" do
    it "takes one IPv4 or IPv6 address, trimmed" do
      expect(described_class.parse(" 203.0.113.24\n")).to eq("203.0.113.24")
      expect(described_class.parse("2001:db8::1")).to eq("2001:db8::1")
      expect(described_class.parse("::ffff:203.0.113.24")).to eq("::ffff:203.0.113.24")
    end

    it "refuses ranges, lists and anything else" do
      ["", "  ", nil, "203.0.113.0/24", "2001:db8::/32", "203.0.113.24, 10.0.0.1", "203.0.113", "unknown",
       "203.0.113.24\r\nX-Evil: 1", "999.1.1.1"].each do |value|
        expect(described_class.parse(value)).to be_nil, "expected #{value.inspect} to be refused"
      end
    end

    it "raises for a value passed on purpose that isn't one address, and treats blank as none" do
      expect { described_class.parse!("203.0.113.0/24") }.to raise_error(ArgumentError, /one IP address/)
      expect { described_class.parse!("a, b") }.to raise_error(ArgumentError)
      expect(described_class.parse!(nil)).to be_nil
      expect(described_class.parse!(" ")).to be_nil
    end
  end

  describe "on the client" do
    # The step-up starts a sign-in challenge from the server, where IP rules apply.
    it "sends the address on secret-key calls" do
      start_sign_in(Scute::Client.new(**options, client_ip: " 203.0.113.24 "))

      expect(fake.seen.last).to have_attributes(path: "/v1/auth/app1/challenges", auth: "Bearer sk_test")
      expect(sent_ip).to eq("203.0.113.24")
    end

    it "sends nothing when no address was given" do
      start_sign_in(client)
      client.users.create("ada@example.com")

      expect(fake.seen.map(&:headers)).to all(satisfy { |h| !h.key?(header) })
    end

    it "lets one call pass another address, leaving the client as it was" do
      scute = Scute::Client.new(**options, client_ip: "203.0.113.24")
      scute.authz.check(user_id: "user1", action: "read")

      scute.with_client_ip("2001:db8::7").users.create("ada@example.com")
      expect(fake.seen.last).to have_attributes(path: "/v1/auth/app1/users")
      expect(sent_ip).to eq("2001:db8::7")

      scute.authz.check(user_id: "user1", action: "read")
      expect(sent_ip).to eq("203.0.113.24")
      expect(scute.with_client_ip(nil).client_ip).to be_nil
    end

    it "refuses an address that isn't one IP, before any call" do
      expect { Scute::Client.new(**options, client_ip: "203.0.113.0/24") }.to raise_error(ArgumentError, /one IP address/)
      expect { client.with_client_ip("203.0.113.24, 10.0.0.1") }.to raise_error(ArgumentError)
      expect(fake.seen).to be_empty
    end

    it "never sends it on calls made with a user's own session or a task token" do
      scute = Scute::Client.new(**options, client_ip: "203.0.113.24")
      scute.sessions.current_user("tok")
      expect(fake.seen.last.headers).not_to have_key(header)

      run = harness(fake, client: scute).run(acts_for: "user1")
      run.whoami
      expect(fake.seen.find { |s| s.path.end_with?("/tasks") }.headers[header]).to eq("203.0.113.24")
      expect(fake.seen.last).to have_attributes(path: "/v1/auth/app1/agent/whoami")
      expect(fake.seen.last.headers).not_to have_key(header)
    end
  end

  describe "with" do
    it "applies to clients without their own address, for the block only" do
      own = Scute::Client.new(**options, client_ip: "198.51.100.1")

      described_class.with("203.0.113.24") do
        start_sign_in(client)
        expect(sent_ip).to eq("203.0.113.24")
        start_sign_in(own)
        expect(sent_ip).to eq("198.51.100.1")
      end

      start_sign_in(client)
      expect(fake.seen.last.headers).not_to have_key(header)
      expect(described_class.current).to be_nil
    end
  end

  describe Scute::ClientIP::Middleware do
    def env(remote_addr, extra = {}) = Rack::MockRequest.env_for("/", { "REMOTE_ADDR" => remote_addr }.merge(extra))

    def seen_in(env)
      seen = :unset
      app = described_class.new(lambda do |_env|
        seen = Scute::ClientIP.current
        [200, {}, []]
      end)
      app.call(env)
      seen
    end

    it "sets the request's address for every client while the request runs" do
      app = described_class.new(lambda do |_env|
        start_sign_in(client)
        [200, {}, []]
      end)
      app.call(env("203.0.113.24"))

      expect(sent_ip).to eq("203.0.113.24")
      expect(Scute::ClientIP.current).to be_nil
    end

    it "uses the address Rails worked out, then Rack's, never X-Forwarded-For from anyone" do
      expect(seen_in(env("10.0.0.2", "action_dispatch.remote_ip" => "198.51.100.9"))).to eq("198.51.100.9")
      # Rack skips its trusted (private) proxies only.
      expect(seen_in(env("10.0.0.2", "HTTP_X_FORWARDED_FOR" => "203.0.113.24"))).to eq("203.0.113.24")
      expect(seen_in(env("198.51.100.1", "HTTP_X_FORWARDED_FOR" => "203.0.113.24"))).to eq("198.51.100.1")
    end

    it "sends nothing when the request's address isn't one IP" do
      expect(seen_in(env("unix-socket"))).to be_nil
    end
  end

  describe "in controllers" do
    let(:controller_class) do
      Class.new do
        include Scute::Authentication
        include Scute::Authorization

        attr_reader :request

        def initialize(request) = @request = request
      end
    end

    around do |example|
      saved = %w[SCUTE_APP_ID SCUTE_SECRET SCUTE_BASE_URL].to_h { |k| [k, ENV.fetch(k, nil)] }
      ENV.update("SCUTE_APP_ID" => "app1", "SCUTE_SECRET" => "sk_test", "SCUTE_BASE_URL" => "https://scute.test")
      example.run
    ensure
      ENV.update(saved)
    end

    def scute_client_for(request)
      controller_class.new(request).scute_client.tap { |c| c.http.instance_variable_set(:@transport, fake) }
    end

    it "fills the address from request.remote_ip (Rails)" do
      request = Struct.new(:remote_ip, :ip).new("203.0.113.24", "10.0.0.2")
      start_sign_in(scute_client_for(request))

      expect(sent_ip).to eq("203.0.113.24")
    end

    it "fills the address from Rack::Request#ip" do
      request = Rack::Request.new(Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "2001:db8::5"))
      expect(scute_client_for(request).client_ip).to eq("2001:db8::5")
    end

    it "skips an address that isn't one IP instead of failing the request" do
      request = Struct.new(:remote_ip).new("203.0.113.24, 10.0.0.1")
      start_sign_in(scute_client_for(request))

      expect(fake.seen.last.headers).not_to have_key(header)
    end
  end
end
