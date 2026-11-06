defmodule Oat.OAuth2.TokenResponse do
  @moduledoc """
  Successful token responses (RFC 6749 §5.1).
  """

  alias Oat.OAuth2.Scope

  @doc """
  Headers every token endpoint response must carry, success or error (§5.1, §5.2).
  """
  @spec headers() :: [{String.t(), String.t()}]
  def headers do
    [
      {"content-type", "application/json;charset=UTF-8"},
      {"cache-control", "no-store"},
      {"pragma", "no-cache"}
    ]
  end

  @doc """
  Builds the response parameters.

  Required: `:access_token`. Optional: `:token_type` (default `"Bearer"`),
  `:expires_in`, `:refresh_token`, `:scope` (granted) and `:requested_scope`.

  `scope` is included only when it differs from `requested_scope` (§3.3, §5.1).
  If no requested scope is given, the granted scope is always included.
  """
  @spec build(keyword()) :: %{String.t() => String.t() | non_neg_integer()}
  def build(opts) do
    granted = Keyword.get(opts, :scope)
    requested = Keyword.get(opts, :requested_scope)

    scope =
      cond do
        is_nil(granted) -> nil
        is_nil(requested) or Scope.changed?(requested, granted) -> Scope.format(granted)
        true -> nil
      end

    [
      {"access_token", Keyword.fetch!(opts, :access_token)},
      {"token_type", Keyword.get(opts, :token_type, "Bearer")},
      {"expires_in", Keyword.get(opts, :expires_in)},
      {"refresh_token", Keyword.get(opts, :refresh_token)},
      {"scope", scope}
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
    |> Map.new()
  end
end
