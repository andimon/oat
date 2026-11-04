defmodule Oat.OAuth2.ClientAuthTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.ClientAuth

  doctest ClientAuth

  describe "basic auth" do
    test "round-trips credentials that need form encoding" do
      creds = {"client:1", "s3cr3t/+= ü"}
      assert ClientAuth.decode_basic(ClientAuth.encode_basic(creds)) == {:ok, creds}
    end

    test "decodes the RFC example and accepts any case for the scheme" do
      assert ClientAuth.decode_basic("basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3") ==
               {:ok, {"s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw"}}
    end

    test "rejects malformed headers" do
      for header <- ["Bearer abc", "Basic !!!", "Basic " <> Base.encode64("nocolon"), "Basic"] do
        assert ClientAuth.decode_basic(header) == {:error, :invalid_client}
      end
    end
  end

  describe "extract/2" do
    @header ClientAuth.encode_basic({"id", "secret"})

    test "reads the header" do
      assert ClientAuth.extract(@header, %{}) == {:ok, {:basic, {"id", "secret"}}}
    end

    test "reads body credentials" do
      assert ClientAuth.extract(nil, %{"client_id" => "id", "client_secret" => "s"}) ==
               {:ok, {:body, {"id", "s"}}}
    end

    test "identifies a public client by client_id alone" do
      assert ClientAuth.extract(nil, %{"client_id" => "id"}) == {:ok, {:public, "id"}}
      assert ClientAuth.extract(nil, %{}) == {:ok, :none}
    end

    test "rejects using the header and body credentials together" do
      assert ClientAuth.extract(@header, %{"client_secret" => "secret"}) ==
               {:error, :invalid_request}
    end

    test "allows a matching client_id in the body alongside the header" do
      assert ClientAuth.extract(@header, %{"client_id" => "id"}) ==
               {:ok, {:basic, {"id", "secret"}}}

      assert ClientAuth.extract(@header, %{"client_id" => "other"}) ==
               {:error, :invalid_request}
    end
  end

  test "secret_matches?/2" do
    assert ClientAuth.secret_matches?("abc", "abc")
    refute ClientAuth.secret_matches?("abc", "abd")
    refute ClientAuth.secret_matches?(nil, "abc")
  end
end
