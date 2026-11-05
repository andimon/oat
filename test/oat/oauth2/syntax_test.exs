defmodule Oat.OAuth2.SyntaxTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.Syntax

  @all_funs [
    :client_id?,
    :client_secret?,
    :response_type?,
    :scope?,
    :scope_token?,
    :state?,
    :error?,
    :error_description?,
    :grant_type?,
    :code?,
    :access_token?,
    :token_type?,
    :expires_in?,
    :username?,
    :password?,
    :refresh_token?,
    :name?,
    :uri_reference?
  ]

  @min0 [:client_id?, :client_secret?, :username?, :password?]
  @min1 [
    :state?,
    :code?,
    :access_token?,
    :refresh_token?,
    :scope_token?,
    :error?,
    :error_description?,
    :expires_in?,
    :name?
  ]
  @composite [
    :scope?,
    :response_type?,
    :grant_type?,
    :token_type?,
    :uri_reference?
  ]

  @vschar_funs [:client_id?, :client_secret?, :state?, :code?, :access_token?, :refresh_token?]

  defp check(funs, input, expected) do
    for fun <- funs do
      assert apply(Syntax, fun, [input]) == expected,
             "#{fun}(#{inspect(input)}) expected #{expected}"
    end
  end

  describe "non-binary input" do
    test "every function returns false" do
      for input <- [nil, 1, :atom, ~c"abc", ["a"], %{}] do
        check(@all_funs, input, false)
      end
    end
  end

  describe "minimum length" do
    test "* rules accept the empty string" do
      check(@min0, "", true)
    end

    test "1* rules reject the empty string and accept one valid char" do
      check(@min1, "", false)
      check([:state?, :code?, :access_token?, :refresh_token?], "a", true)
      check([:scope_token?, :error?, :error_description?, :name?], "a", true)
      check([:expires_in?], "0", true)
    end

    test "composite rules reject the empty string" do
      check(@composite, "", false)
    end
  end

  describe "VSCHAR (%x20-7E)" do
    test "boundaries" do
      check(@vschar_funs, <<0x1F>>, false)
      check(@vschar_funs, " ", true)
      check(@vschar_funs, "~", true)
      check(@vschar_funs, <<0x7F>>, false)
    end

    test "control and non-ASCII characters" do
      for input <- ["\t", "\n", "\r", "é"], do: check(@vschar_funs, input, false)
    end
  end

  describe "NQCHAR (scope_token?)" do
    test "boundaries" do
      refute Syntax.scope_token?(" ")
      assert Syntax.scope_token?("!")
      refute Syntax.scope_token?(~s("))
      assert Syntax.scope_token?("#")
      assert Syntax.scope_token?("[")
      refute Syntax.scope_token?("\\")
      assert Syntax.scope_token?("]")
      assert Syntax.scope_token?("~")
      refute Syntax.scope_token?(<<0x7F>>)
      refute Syntax.scope_token?("é")
    end
  end

  describe "NQSCHAR (error?, error_description?)" do
    test "same as NQCHAR except space is allowed" do
      check([:error?, :error_description?], " ", true)
      check([:error?, :error_description?], "!", true)
      check([:error?, :error_description?], ~s("), false)
      check([:error?, :error_description?], "\\", false)
      check([:error?, :error_description?], "[", true)
      check([:error?, :error_description?], "]", true)
      check([:error?, :error_description?], "~", true)
      check([:error?, :error_description?], "\t", false)
      check([:error?, :error_description?], <<0x7F>>, false)
      check([:error?, :error_description?], "é", false)
    end
  end

  describe "DIGIT (expires_in?)" do
    test "boundaries and non-digit input" do
      assert Syntax.expires_in?("0")
      assert Syntax.expires_in?("9")
      refute Syntax.expires_in?("/")
      refute Syntax.expires_in?(":")

      for input <- ["-1", "+1", "1.5", "12a", "1 2"], do: refute(Syntax.expires_in?(input))
    end
  end

  describe "name-char (name?)" do
    test "accepted characters" do
      for input <- ~w(a z A Z 0 9 - . _), do: assert(Syntax.name?(input))
    end

    test "characters adjacent to the ranges are rejected" do
      for input <- ["@", "[", "`", "{", "/", ":", " "], do: refute(Syntax.name?(input))
    end
  end

  describe "response-char (response_type?)" do
    test "alphanumerics and underscore are accepted" do
      for input <- ~w(a Z 0 9 _), do: assert(Syntax.response_type?(input))
    end

    test "narrower than name-char: - and . are rejected" do
      refute Syntax.response_type?("a-b")
      refute Syntax.response_type?("a.b")
      assert Syntax.name?("a-b")
      assert Syntax.name?("a.b")
    end
  end

  describe "UNICODECHARNOCRLF (username?, password?)" do
    test "ASCII range" do
      check([:username?, :password?], "\t", true)
      check([:username?, :password?], "\n", false)
      check([:username?, :password?], "\r", false)
      check([:username?, :password?], "\r\n", false)
      check([:username?, :password?], <<0x08>>, false)
      check([:username?, :password?], <<0x1F>>, false)
      check([:username?, :password?], " ", true)
      check([:username?, :password?], "~", true)
      check([:username?, :password?], <<0x7F>>, false)
    end

    test "NUL is not in the grammar" do
      check([:username?, :password?], <<0>>, false)
    end

    test "non-ASCII ranges and their boundaries" do
      for input <- ["\u0080", "퟿", "", "�", "\u{10000}", "\u{10FFFF}"] do
        check([:username?, :password?], input, true)
      end

      # valid UTF-8, but noncharacters outside the grammar
      for input <- ["￾", "￿"], do: check([:username?, :password?], input, false)
    end

    test "invalid UTF-8" do
      for input <- [<<0xFF>>, <<0xED, 0xA0, 0x80>>, <<0xE2, 0x82>>] do
        check([:username?, :password?], input, false)
      end
    end
  end

  describe "space-delimited lists (scope?, response_type?)" do
    test "one, two and three tokens" do
      assert Syntax.scope?("a")
      assert Syntax.scope?("a b")
      assert Syntax.scope?("a b c")
      assert Syntax.response_type?("code")
      assert Syntax.response_type?("code id_token")
      assert Syntax.response_type?("code id_token token")
    end

    test "empty tokens are rejected" do
      for fun <- [:scope?, :response_type?],
          input <- [" a", "a ", "a  b", " "] do
        check([fun], input, false)
      end
    end

    test "a bad token anywhere is rejected" do
      for input <- [~s(") <> " b c", "a " <> ~s(") <> " c", "a b " <> ~s(")] do
        refute Syntax.scope?(input)
      end

      for input <- ["a- b c", "a b- c", "a b c-"], do: refute(Syntax.response_type?(input))
    end

    test "only a space separates tokens" do
      for fun <- [:scope?, :response_type?], input <- ["a\tb", "a\nb"] do
        check([fun], input, false)
      end
    end
  end

  describe "name / URI-reference alternation (grant_type?, token_type?)" do
    test "a name" do
      check([:grant_type?, :token_type?], "authorization_code", true)
      check([:grant_type?, :token_type?], "Bearer", true)
    end

    test "a URI that is not a name" do
      check([:grant_type?, :token_type?], "urn:ietf:params:oauth:grant-type:jwt-bearer", true)
      check([:grant_type?, :token_type?], "https://x/y", true)
    end

    test "neither" do
      check([:grant_type?, :token_type?], "a b", false)
      check([:grant_type?, :token_type?], "", false)
    end
  end

  describe "uri_reference?" do
    test "absolute URI" do
      assert Syntax.uri_reference?("https://example.com/cb?x=1#f")
    end

    test "relative references" do
      for input <- ["/cb", "cb", "?x=1", "#frag"], do: assert(Syntax.uri_reference?(input))
    end

    test "the empty string is rejected on purpose" do
      refute Syntax.uri_reference?("")
    end

    test "malformed input" do
      for input <- ["http://[bad", "a b", <<0xFF>>], do: refute(Syntax.uri_reference?(input))
    end
  end

  describe "realistic values and single bad characters" do
    test "happy paths" do
      assert Syntax.client_id?("s6BhdRkqt3")
      assert Syntax.scope?("read write")
      assert Syntax.response_type?("code id_token")
      assert Syntax.error?("invalid_request")
      assert Syntax.expires_in?("3600")
    end

    test "one bad character in the middle or at the end" do
      assert Syntax.state?("abc")
      refute Syntax.state?("a\nc")
      refute Syntax.state?("ab\n")
      assert Syntax.expires_in?("3600")
      refute Syntax.expires_in?("36a0")
      refute Syntax.expires_in?("360a")
      assert Syntax.scope_token?("read")
      refute Syntax.scope_token?("re\"d")
      refute Syntax.scope_token?("rea\"")
      refute Syntax.name?("ab cd")
      refute Syntax.name?("abcd ")
      refute Syntax.username?("ab\ncd")
      refute Syntax.username?("abcd\n")
    end
  end

  describe "functions documented as identical agree" do
    @samples [
      "",
      " ",
      "a",
      "a b",
      "abc-def",
      "x.y_z",
      "\t",
      "\n",
      "é",
      "\\",
      ~s("),
      "~",
      <<0x7F>>,
      <<0xFF>>,
      "https://x/y",
      "3600",
      nil
    ]

    for {name, group} <- [
          client: [:client_id?, :client_secret?],
          vschar_1: [:state?, :code?, :access_token?, :refresh_token?],
          nqschar: [:error?, :error_description?],
          type: [:grant_type?, :token_type?],
          credentials: [:username?, :password?]
        ] do
      test "#{name}: #{inspect(group)}" do
        [first | rest] = unquote(group)

        for input <- @samples, fun <- rest do
          assert apply(Syntax, fun, [input]) == apply(Syntax, first, [input]),
                 "#{fun} and #{first} disagree on #{inspect(input)}"
        end
      end
    end
  end
end
