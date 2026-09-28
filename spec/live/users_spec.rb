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

  it "answers nil for an identifier nobody uses (as users.find_by_identifier documents)" do
    stranger = world.next_email
    found = client.users.find_by_identifier(stranger)
    world.track_user(found["id"]) if found # if the lookup made one, it goes too

    pending("users.find_by_identifier returns a new user for an identifier nobody uses, instead of nil")
    expect(found).to be_nil
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
