defmodule Oat.OAuth2.Scope do
  @moduledoc """
  Access token scope handling: RFC 6749 §3.3
  (https://www.rfc-editor.org/rfc/rfc6749#section-3.3).

  A scope is a list of space-delimited, case-sensitive strings. Order does not
  matter, so scopes are represented as a `MapSet`.
  """

  alias Oat.OAuth2.Syntax

  @type t :: MapSet.t(String.t())

  @doc """
  Parses a `scope` parameter value. `nil` (parameter omitted) parses to an empty scope.

      iex> Oat.OAuth2.Scope.parse("read write")
      {:ok, MapSet.new(["read", "write"])}

      iex> Oat.OAuth2.Scope.parse("read  write")
      {:error, :invalid_scope}
  """
  @spec parse(String.t() | nil) :: {:ok, t()} | {:error, :invalid_scope}
  def parse(nil), do: {:ok, MapSet.new()}

  def parse(value) when is_binary(value) do
    if Syntax.scope?(value) do
      {:ok, value |> String.split(" ") |> MapSet.new()}
    else
      {:error, :invalid_scope}
    end
  end

  def parse(_), do: {:error, :invalid_scope}

  @doc """
  Formats a scope as a `scope` parameter value. Tokens are sorted so the output
  is stable. Returns `nil` for an empty scope so the parameter can be left out.
  """
  @spec format(t()) :: String.t() | nil
  def format(scope) do
    case Enum.sort(scope) do
      [] -> nil
      tokens -> Enum.join(tokens, " ")
    end
  end

  @doc """
  Resolves the scope to grant from the requested scope (§3.3).

  * An empty request falls back to `default`. If there is no default either,
    the request fails with `:invalid_scope`, as §3.3 requires.
  * A request that asks for anything outside `allowed` fails with `:invalid_scope`.

  The authorization server may still grant less than requested; if it does, the
  token response must include the granted scope (see `changed?/2`).
  """
  @spec resolve(t(), t(), t()) :: {:ok, t()} | {:error, :invalid_scope}
  def resolve(requested, allowed, default \\ MapSet.new()) do
    requested = if Enum.empty?(requested), do: default, else: requested

    if not Enum.empty?(requested) and MapSet.subset?(requested, allowed),
      do: {:ok, requested},
      else: {:error, :invalid_scope}
  end

  @doc """
  Whether the granted scope differs from the requested one. When true the token
  response must include `scope` (§3.3, §5.1).
  """
  @spec changed?(requested :: t(), granted :: t()) :: boolean()
  def changed?(requested, granted), do: not MapSet.equal?(requested, granted)
end
