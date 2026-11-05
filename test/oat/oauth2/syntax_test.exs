defmodule Oat.OAuth2.SyntaxTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.Syntax

  # Every public validator, read from the module so new ones are covered automatically.
  @all_funs for {name, 1} <- Syntax.__info__(:functions), do: name

  @expects_zero_or_more_characters [:client_id?, :client_secret?, :username?, :password?]
  @expects_one_or_more_characters [
    :state?,
    :code?,
    :access_token?,
    :refresh_token?,
    :scope_token?,
    :error?,
    :error_description?,
    :expires_in?,
    :name?,
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

  describe "coverage guard" do
    test "every public function is classified by minimum length" do
      assert Enum.sort(@all_funs) ==
               Enum.sort(@expects_zero_or_more_characters ++ @expects_one_or_more_characters),
             "add new validators to a minimum-length group"
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
      check(@expects_zero_or_more_characters, "", true)
    end

    test "1* rules reject the empty string and accept one valid char" do
      check(@expects_one_or_more_characters, "", false)
      check([:state?, :code?, :access_token?, :refresh_token?], "a", true)
      check([:scope_token?, :error?, :error_description?, :name?], "a", true)
      check([:expires_in?], "0", true)
    end
  end

  # Each case below is one test: the input is arranged in the table, `check/3`
  # acts on every function listed for the rule, and asserts the expected result.

  describe "VSCHAR (%x20-7E)" do
    for {label, input, expected} <- [
          {"0x1F is rejected", <<0x1F>>, false},
          {"space (0x20) is accepted", " ", true},
          {"~ (0x7E) is accepted", "~", true},
          {"DEL (0x7F) is rejected", <<0x7F>>, false},
          {"tab is rejected", "\t", false},
          {"newline is rejected", "\n", false},
          {"carriage return is rejected", "\r", false},
          {"non-ASCII é is rejected", "é", false}
        ] do
      test label do
        check(@vschar_funs, unquote(input), unquote(expected))
      end
    end
  end

  describe "NQCHAR (scope_token?)" do
    for {label, input, expected} <- [
          {"space is rejected", " ", false},
          {"! (0x21) is accepted", "!", true},
          {"double quote (0x22) is rejected", ~s("), false},
          {"# (0x23) is accepted", "#", true},
          {"[ (0x5B) is accepted", "[", true},
          {"backslash (0x5C) is rejected", "\\", false},
          {"] (0x5D) is accepted", "]", true},
          {"~ (0x7E) is accepted", "~", true},
          {"DEL (0x7F) is rejected", <<0x7F>>, false},
          {"non-ASCII é is rejected", "é", false}
        ] do
      test label do
        check([:scope_token?], unquote(input), unquote(expected))
      end
    end
  end

  describe "NQSCHAR (error?, error_description?)" do
    for {label, input, expected} <- [
          {"space is accepted", " ", true},
          {"! (0x21) is accepted", "!", true},
          {"double quote (0x22) is rejected", ~s("), false},
          {"[ (0x5B) is accepted", "[", true},
          {"backslash (0x5C) is rejected", "\\", false},
          {"] (0x5D) is accepted", "]", true},
          {"~ (0x7E) is accepted", "~", true},
          {"tab is rejected", "\t", false},
          {"DEL (0x7F) is rejected", <<0x7F>>, false},
          {"non-ASCII é is rejected", "é", false}
        ] do
      test label do
        check([:error?, :error_description?], unquote(input), unquote(expected))
      end
    end
  end

  describe "DIGIT (expires_in?)" do
    for {label, input, expected} <- [
          {"0 is accepted", "0", true},
          {"9 is accepted", "9", true},
          {"/ (0x2F) is rejected", "/", false},
          {": (0x3A) is rejected", ":", false},
          {"negative sign is rejected", "-1", false},
          {"positive sign is rejected", "+1", false},
          {"decimal point is rejected", "1.5", false},
          {"trailing letter is rejected", "12a", false},
          {"embedded space is rejected", "1 2", false}
        ] do
      test label do
        check([:expires_in?], unquote(input), unquote(expected))
      end
    end
  end

  describe "name-char (name?)" do
    for char <- ~w(a z A Z 0 9 - . _) do
      test "#{char} is accepted" do
        check([:name?], unquote(char), true)
      end
    end

    # characters just outside the letter and digit ranges, plus separators
    for char <- ["@", "[", "`", "{", "/", ":", " "] do
      test "#{inspect(char)} is rejected" do
        check([:name?], unquote(char), false)
      end
    end
  end

  describe "response-char (response_type?)" do
    for char <- ~w(a Z 0 9 _) do
      test "#{char} is accepted" do
        check([:response_type?], unquote(char), true)
      end
    end

    # narrower than name-char, so the two are not confused
    for char <- ["a-b", "a.b"] do
      test "#{char} is rejected by response_type? but accepted by name?" do
        check([:response_type?], unquote(char), false)
        check([:name?], unquote(char), true)
      end
    end
  end

  describe "UNICODECHARNOCRLF (username?, password?)" do
    for {label, input, expected} <- [
          {"tab (0x09) is accepted", "\t", true},
          {"newline is rejected", "\n", false},
          {"carriage return is rejected", "\r", false},
          {"CRLF is rejected", "\r\n", false},
          {"NUL is rejected", <<0x00>>, false},
          {"0x08 is rejected", <<0x08>>, false},
          {"0x1F is rejected", <<0x1F>>, false},
          {"space (0x20) is accepted", " ", true},
          {"~ (0x7E) is accepted", "~", true},
          {"DEL (0x7F) is rejected", <<0x7F>>, false},
          {"U+0080 is accepted", <<0x80::utf8>>, true},
          {"U+D7FF is accepted", <<0xD7FF::utf8>>, true},
          {"U+E000 is accepted", <<0xE000::utf8>>, true},
          {"U+FFFD is accepted", <<0xFFFD::utf8>>, true},
          {"U+FFFE is rejected (valid UTF-8 but not in the grammar)", <<0xFFFE::utf8>>, false},
          {"U+FFFF is rejected (valid UTF-8 but not in the grammar)", <<0xFFFF::utf8>>, false},
          {"U+10000 is accepted", <<0x10000::utf8>>, true},
          {"U+10FFFF is accepted", <<0x10FFFF::utf8>>, true},
          {"invalid byte 0xFF is rejected", <<0xFF>>, false},
          {"encoded surrogate is rejected", <<0xED, 0xA0, 0x80>>, false},
          {"truncated sequence is rejected", <<0xE2, 0x82>>, false}
        ] do
      test label do
        check([:username?, :password?], unquote(input), unquote(expected))
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
