defmodule Oat.OAuth2.TokenResponseTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.TokenResponse

  test "headers/0 forbids caching" do
    headers = TokenResponse.headers()
    assert {"cache-control", "no-store"} in headers
    assert {"pragma", "no-cache"} in headers
  end

  test "build/1 includes only the parameters that are set" do
    assert TokenResponse.build(access_token: "at", expires_in: 3600, refresh_token: "rt") == %{
             "access_token" => "at",
             "token_type" => "Bearer",
             "expires_in" => 3600,
             "refresh_token" => "rt"
           }
  end

  test "build/1 includes scope only when it differs from the request" do
    requested = MapSet.new(["read", "write"])

    refute Map.has_key?(
             TokenResponse.build(
               access_token: "at",
               scope: requested,
               requested_scope: requested
             ),
             "scope"
           )

    assert TokenResponse.build(
             access_token: "at",
             scope: MapSet.new(["read"]),
             requested_scope: requested
           )["scope"] == "read"

    assert TokenResponse.build(access_token: "at", scope: requested)["scope"] == "read write"
  end
end
