defmodule Oat.ValidatorHelpers do
  @moduledoc """
  Helpers for testing boolean validator modules in an arrange, act, assert style.

  A *case* is an `{input, expected}` tuple. Typical use:

      import Oat.ValidatorHelpers

      test "empty string is accepted" do
        # Arrange
        cases = [{"", true}]

        # Act
        results = check_all(MyValidator, [:client_id?], cases)

        # Assert
        assert_as_expected(results)
      end
  """

  import ExUnit.Assertions

  @doc """
  Act: calls every function in `funs` on `module` with every case.

  Returns a list of `{fun, input, expected, actual}` tuples.
  """
  def check_all(module, funs, cases) do
    for fun <- funs, {input, expected} <- cases do
      {fun, input, expected, apply(module, fun, [input])}
    end
  end

  @doc "Assert: every actual result equals the expected one."
  def assert_as_expected(results) do
    for {fun, input, expected, actual} <- results do
      assert actual == expected,
             "#{fun}(#{inspect(input)}) expected #{expected}, got #{actual}"
    end

    :ok
  end
end
