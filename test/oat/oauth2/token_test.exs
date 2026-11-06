defmodule Oat.OAuth2.TokenTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.{Syntax, Token}

  test "generate/1 returns unique URL-safe values that fit the token syntax" do
    tokens = for _ <- 1..100, do: Token.generate()

    assert length(Enum.uniq(tokens)) == 100
    assert Enum.all?(tokens, &Syntax.access_token?/1)
    assert Enum.all?(tokens, &(&1 =~ ~r/\A[A-Za-z0-9_-]{43}\z/))
  end

  test "generate/1 refuses less than 128 bits of entropy" do
    assert_raise FunctionClauseError, fn -> Token.generate(8) end
  end

  test "hash/1 is stable and differs from the input" do
    assert Token.hash("abc") == Token.hash("abc")
    refute Token.hash("abc") == "abc"
  end

  test "expiry helpers" do
    issued = ~U[2026-01-01 00:00:00Z]
    expires = Token.expires_at(issued, 600)

    assert expires == ~U[2026-01-01 00:10:00Z]
    refute Token.expired?(expires, ~U[2026-01-01 00:09:59Z])
    assert Token.expired?(expires, expires)
    assert Token.expires_in(expires, issued) == 600
    assert Token.expires_in(expires, ~U[2026-01-02 00:00:00Z]) == 0
  end
end
