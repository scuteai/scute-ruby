# frozen_string_literal: true

require_relative "live_helper"

RSpec.describe "Live: users (scute-ruby, secret key)", :live, order: :defined do
  before(:context) { @user = { email: world.next_email } }

  it "creates a user (users.create)" do
    created = client.users.create(@user[:email])["user"]
    world.track_user(created["id"])
    @user[:id] = created["id"]

    expect(created).to include("email" => @user[:email], "status" => "active")
  end

  it "gets them by id (users.get)" do
    expect(client.users.get(@user[:id])["user"]).to include("id" => @user[:id], "email" => @user[:email])
  end

  it "finds them by identifier (users.find_by_identifier)" do
    expect(client.users.find_by_identifier(@user[:email])).to include("id" => @user[:id])
  end

  it "answers nil for an identifier nobody uses, and makes nobody" do
    stranger = world.next_email
    found = client.users.find_by_identifier(stranger)
    world.track_user(found["id"]) if found # should the lookup ever make one, it goes too

    expect(found).to be_nil
    expect(client.users.list(email: stranger)["users"]).to eq([])
    unused_phone = "+1312555#{format('%04d', 100 + ((world.phone[-2..].to_i + 50) % 100))}" # not this run's SMS user
    expect(client.users.find_by_identifier(unused_phone)).to be_nil
  end

  it "matches exactly, though the search behind it is loose (email in any case, phone as digits)" do
    near = world.next_email.sub("+scute_test@", "0+scute_test@") # the loose search answers both
    other = client.users.create(near)["user"]
    world.track_user(other["id"])

    expect(client.users.find_by_identifier(@user[:email].upcase)).to include("id" => @user[:id])
    expect(client.users.find_by_identifier(near)).to include("id" => other["id"])

    digits = format("%04d", 100 + ((world.phone[-2..].to_i + 25) % 100))
    by_phone = client.users.create("+1312555#{digits}")["user"]
    world.track_user(by_phone["id"])
    expect(client.users.find_by_identifier("+1 (312) 555-#{digits}")).to include("id" => by_phone["id"])
  end

  it "lists them (users.list)" do
    listed = client.users.list(email: @user[:email])

    expect(listed["users"].map { |u| u["id"] }).to eq([@user[:id]])
  end

  it "updates them (users.update: authz_attributes)" do
    updated = client.users.update(@user[:id], authz_attributes: { plan: "pro" })["user"]

    expect(updated["authz_attributes"]).to eq("plan" => "pro")
  end

  it "deactivates and activates them" do
    expect(client.users.deactivate(@user[:id])["user"]["status"]).to eq("inactive")
    expect(client.users.activate(@user[:id])["user"]["status"]).to eq("active")
  end

  it "deletes them (users.delete)" do
    expect(client.users.delete(@user[:id])).to include("message" => "ok")
    expect { client.users.get(@user[:id]) }.to raise_error(Scute::APIError) { |e| expect(e.status).to eq(404) }
  end
end
