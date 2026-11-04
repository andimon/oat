defmodule Oat.OAuth2.RedirectURITest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.RedirectURI

  doctest RedirectURI

  test "valid?/1 needs an absolute URI without a fragment" do
    assert RedirectURI.valid?("https://client.example.com/cb")
    assert RedirectURI.valid?("com.example.app:/oauth")
    refute RedirectURI.valid?("/cb")
    refute RedirectURI.valid?("https://client.example.com/cb#frag")
    refute RedirectURI.valid?(nil)
  end

  describe "resolve/2" do
    @registered ["https://a.example/cb", "https://b.example/cb"]

    test "accepts an exact match" do
      assert RedirectURI.resolve("https://b.example/cb", @registered) ==
               {:ok, "https://b.example/cb"}
    end

    test "rejects anything that is not an exact match" do
      assert RedirectURI.resolve("https://b.example/cb/", @registered) ==
               {:error, :invalid_redirect_uri}

      assert RedirectURI.resolve("https://B.example/cb", @registered) ==
               {:error, :invalid_redirect_uri}
    end

    test "falls back to the only registered URI when the parameter is omitted" do
      assert RedirectURI.resolve(nil, ["https://a.example/cb"]) == {:ok, "https://a.example/cb"}
      assert RedirectURI.resolve(nil, @registered) == {:error, :missing_redirect_uri}
      assert RedirectURI.resolve(nil, []) == {:error, :missing_redirect_uri}
    end
  end

  describe "append/3" do
    test "adds query parameters and keeps the existing query" do
      assert RedirectURI.append("https://c.example/cb", [code: "a b", state: "xyz"], :query) ==
               "https://c.example/cb?code=a+b&state=xyz"

      assert RedirectURI.append("https://c.example/cb?x=1", %{"code" => "c"}, :query) ==
               "https://c.example/cb?x=1&code=c"
    end

    test "puts implicit grant parameters in the fragment" do
      assert RedirectURI.append(
               "https://c.example/cb?x=1",
               [access_token: "t", token_type: "Bearer"],
               :fragment
             ) == "https://c.example/cb?x=1#access_token=t&token_type=Bearer"
    end
  end
end
