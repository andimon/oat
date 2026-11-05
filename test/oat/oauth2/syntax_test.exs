defmodule Oat.OAuth2.SyntaxTest do
  use ExUnit.Case, async: true

  import Oat.ValidatorHelpers

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

  describe "every validator is in a group" do
    test "every public function is classified by minimum length" do
      # Arrange
      public = @all_funs
      classified = @expects_zero_or_more_characters ++ @expects_one_or_more_characters

      # Act
      unclassified = public -- classified
      unknown = classified -- public

      # Assert
      assert unclassified == [],
             "Defined in #{inspect(Syntax)} but not in a group: #{inspect(unclassified)}. " <>
               "Add them to @expects_zero_or_more_characters or " <>
               "@expects_one_or_more_characters in #{inspect(__MODULE__)}."

      assert unknown == [],
             "Listed in a group but not defined in #{inspect(Syntax)}: #{inspect(unknown)}. " <>
               "Check for a typo or a renamed function."
    end
  end

  describe "input that is not a string" do
    test "every function returns false" do
      # Arrange
      cases = [
        {nil, false},
        {1, false},
        {:atom, false},
        {~c"abc", false},
        {["a"], false},
        {%{}, false}
      ]

      # Act
      results = check_all(Syntax, @all_funs, cases)

      # Assert
      assert_as_expected(results)
    end
  end

  describe "empty and single-character input" do
    test "rules that allow zero characters accept the empty string" do
      # Arrange
      cases = [{"", true}]

      # Act
      results = check_all(Syntax, @expects_zero_or_more_characters, cases)

      # Assert
      assert_as_expected(results)
    end

    test "rules that need at least one character reject the empty string" do
      # Arrange
      cases = [{"", false}]

      # Act
      results = check_all(Syntax, @expects_one_or_more_characters, cases)

      # Assert
      assert_as_expected(results)
    end

    test "rules that need at least one character accept a single valid character" do
      # Arrange
      letter_funs = [:state?, :code?, :access_token?, :refresh_token?]
      name_funs = [:scope_token?, :error?, :error_description?, :name?]

      # Act
      results =
        check_all(Syntax, letter_funs, [{"a", true}]) ++
          check_all(Syntax, name_funs, [{"a", true}]) ++
          check_all(Syntax, [:expires_in?], [{"0", true}])

      # Assert
      assert_as_expected(results)
    end
  end

  describe "printable ASCII (VSCHAR): client_id?, state?, code?, tokens" do
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
        # Arrange
        cases = [{unquote(input), unquote(expected)}]

        # Act
        results = check_all(Syntax, @vschar_funs, cases)

        # Assert
        assert_as_expected(results)
      end
    end
  end

  describe "scope token characters (NQCHAR): scope_token?" do
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
        # Arrange
        cases = [{unquote(input), unquote(expected)}]

        # Act
        results = check_all(Syntax, [:scope_token?], cases)

        # Assert
        assert_as_expected(results)
      end
    end
  end

  describe "error text characters (NQSCHAR): error?, error_description?" do
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
        # Arrange
        cases = [{unquote(input), unquote(expected)}]

        # Act
        results = check_all(Syntax, [:error?, :error_description?], cases)

        # Assert
        assert_as_expected(results)
      end
    end
  end

  describe "digits only (DIGIT): expires_in?" do
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
        # Arrange
        cases = [{unquote(input), unquote(expected)}]

        # Act
        results = check_all(Syntax, [:expires_in?], cases)

        # Assert
        assert_as_expected(results)
      end
    end
  end

  describe "name characters: name?" do
    for char <- ~w(a z A Z 0 9 - . _) do
      test "#{char} is accepted" do
        # Arrange
        cases = [{unquote(char), true}]

        # Act
        results = check_all(Syntax, [:name?], cases)

        # Assert
        assert_as_expected(results)
      end
    end

    # characters just outside the letter and digit ranges, plus separators
    for char <- ["@", "[", "`", "{", "/", ":", " "] do
      test "#{inspect(char)} is rejected" do
        # Arrange
        cases = [{unquote(char), false}]

        # Act
        results = check_all(Syntax, [:name?], cases)

        # Assert
        assert_as_expected(results)
      end
    end
  end

  describe "response type characters: response_type?" do
    for char <- ~w(a Z 0 9 _) do
      test "#{char} is accepted" do
        # Arrange
        cases = [{unquote(char), true}]

        # Act
        results = check_all(Syntax, [:response_type?], cases)

        # Assert
        assert_as_expected(results)
      end
    end

    # narrower than name-char, so the two are not confused
    for char <- ["a-b", "a.b"] do
      test "#{char} is rejected by response_type? but accepted by name?" do
        # Arrange
        input = unquote(char)

        # Act
        results =
          check_all(Syntax, [:response_type?], [{input, false}]) ++
            check_all(Syntax, [:name?], [{input, true}])

        # Assert
        assert_as_expected(results)
      end
    end
  end

  describe "username and password characters (UNICODECHARNOCRLF)" do
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
        # Arrange
        cases = [{unquote(input), unquote(expected)}]

        # Act
        results = check_all(Syntax, [:username?, :password?], cases)

        # Assert
        assert_as_expected(results)
      end
    end
  end

  describe "lists separated by spaces: scope?, response_type?" do
    test "one, two and three tokens are accepted" do
      # Arrange
      cases = [{"a", true}, {"a b", true}, {"a b c", true}]

      # Act
      results = check_all(Syntax, [:scope?, :response_type?], cases)

      # Assert
      assert_as_expected(results)
    end

    test "empty tokens are rejected" do
      # Arrange
      cases = [{" a", false}, {"a ", false}, {"a  b", false}, {" ", false}]

      # Act
      results = check_all(Syntax, [:scope?, :response_type?], cases)

      # Assert
      assert_as_expected(results)
    end

    test "a bad token anywhere is rejected" do
      # Arrange
      bad_scopes = [{~s(" b c), false}, {~s(a " c), false}, {~s(a b "), false}]
      bad_response_types = [{"a- b c", false}, {"a b- c", false}, {"a b c-", false}]

      # Act
      results =
        check_all(Syntax, [:scope?], bad_scopes) ++
          check_all(Syntax, [:response_type?], bad_response_types)

      # Assert
      assert_as_expected(results)
    end

    test "only a space separates tokens" do
      # Arrange
      cases = [{"a\tb", false}, {"a\nb", false}]

      # Act
      results = check_all(Syntax, [:scope?, :response_type?], cases)

      # Assert
      assert_as_expected(results)
    end
  end

  describe "a name or a URI: grant_type?, token_type?" do
    test "a name is accepted" do
      # Arrange
      cases = [{"authorization_code", true}, {"Bearer", true}]

      # Act
      results = check_all(Syntax, [:grant_type?, :token_type?], cases)

      # Assert
      assert_as_expected(results)
    end

    test "a URI that is not a name is accepted" do
      # Arrange
      cases = [{"urn:ietf:params:oauth:grant-type:jwt-bearer", true}, {"https://x/y", true}]

      # Act
      results = check_all(Syntax, [:grant_type?, :token_type?], cases)

      # Assert
      assert_as_expected(results)
    end

    test "neither a name nor a URI is rejected" do
      # Arrange
      cases = [{"a b", false}, {"", false}]

      # Act
      results = check_all(Syntax, [:grant_type?, :token_type?], cases)

      # Assert
      assert_as_expected(results)
    end
  end

  describe "URI references: uri_reference?" do
    test "an absolute URI is accepted" do
      # Arrange
      cases = [{"https://example.com/cb?x=1#f", true}]

      # Act
      results = check_all(Syntax, [:uri_reference?], cases)

      # Assert
      assert_as_expected(results)
    end

    test "relative references are accepted" do
      # Arrange
      cases = [{"/cb", true}, {"cb", true}, {"?x=1", true}, {"#frag", true}]

      # Act
      results = check_all(Syntax, [:uri_reference?], cases)

      # Assert
      assert_as_expected(results)
    end

    test "the empty string is rejected on purpose" do
      # Arrange
      cases = [{"", false}]

      # Act
      results = check_all(Syntax, [:uri_reference?], cases)

      # Assert
      assert_as_expected(results)
    end

    test "malformed input is rejected" do
      # Arrange
      cases = [{"http://[bad", false}, {"a b", false}, {<<0xFF>>, false}]

      # Act
      results = check_all(Syntax, [:uri_reference?], cases)

      # Assert
      assert_as_expected(results)
    end
  end

  describe "normal values and one bad character" do
    test "happy paths are accepted" do
      # Arrange
      happy_paths = [
        client_id?: "s6BhdRkqt3",
        scope?: "read write",
        response_type?: "code id_token",
        error?: "invalid_request",
        expires_in?: "3600"
      ]

      # Act
      results = for {fun, input} <- happy_paths, do: hd(check_all(Syntax, [fun], [{input, true}]))

      # Assert
      assert_as_expected(results)
    end

    test "one bad character in the middle or at the end is rejected" do
      # Arrange
      cases = [
        state?: [{"abc", true}, {"a\nc", false}, {"ab\n", false}],
        expires_in?: [{"3600", true}, {"36a0", false}, {"360a", false}],
        scope_token?: [{"read", true}, {~s(re"d), false}, {~s(rea"), false}],
        name?: [{"abcd", true}, {"ab cd", false}, {"abcd ", false}],
        username?: [{"abcd", true}, {"ab\ncd", false}, {"abcd\n", false}]
      ]

      # Act
      results =
        Enum.flat_map(cases, fn {fun, fun_cases} -> check_all(Syntax, [fun], fun_cases) end)

      # Assert
      assert_as_expected(results)
    end
  end

  describe "validators with the same rule give the same answers" do
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
        # Arrange: the first function is the reference for the others
        [reference | others] = unquote(group)
        cases = for input <- @samples, do: {input, apply(Syntax, reference, [input])}

        # Act
        results = check_all(Syntax, others, cases)

        # Assert
        assert_as_expected(results)
      end
    end
  end
end
