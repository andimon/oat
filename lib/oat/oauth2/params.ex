defmodule Oat.OAuth2.Params do
  @moduledoc """
  Request parameter rules shared by the authorization and token endpoints
  (§3.1, §3.2 of RFC 6749, https://www.rfc-editor.org/rfc/rfc6749).

  * Parameters sent without a value are treated as omitted.
  * Request and response parameters must not be included more than once.
  * Unrecognised parameters are ignored.

  Plug's parsers keep only the last value of a repeated parameter, so the
  repetition check has to run on the raw query string or form body.
  """

  @doc """
  Decodes an `application/x-www-form-urlencoded` string and drops empty values.

  Returns `{params, repeated}`: `params` keeps the first value of each name and
  `repeated` lists the names that appear more than once, in order. Each endpoint
  decides what a repeat means; the authorization endpoint, for example, may
  only redirect the error when `client_id` and `redirect_uri` are not repeated
  (§4.1.2.1).

      iex> Oat.OAuth2.Params.decode("response_type=code&client_id=s6&state=")
      {%{"response_type" => "code", "client_id" => "s6"}, []}

      iex> Oat.OAuth2.Params.decode("client_id=s6&scope=a&scope=b")
      {%{"client_id" => "s6", "scope" => "a"}, ["scope"]}
  """
  @spec decode(String.t() | nil) :: {%{String.t() => String.t()}, [String.t()]}
  def decode(nil), do: {%{}, []}

  def decode(raw) when is_binary(raw) do
    {params, repeated} =
      raw
      |> URI.query_decoder(:www_form)
      |> Enum.reject(fn {_, value} -> value == "" end)
      |> Enum.reduce({%{}, []}, fn {name, value}, {params, repeated} ->
        if Map.has_key?(params, name),
          do: {params, [name | repeated]},
          else: {Map.put(params, name, value), repeated}
      end)

    {params, repeated |> Enum.reverse() |> Enum.uniq()}
  end

  @doc """
  Builds a parameter map from name/value pairs, leaving out `nil` values, i.e.
  optional parameters that are not set.

      iex> Oat.OAuth2.Params.compact(error: "access_denied", state: nil)
      %{error: "access_denied"}
  """
  @spec compact(Enumerable.t()) :: map()
  def compact(pairs), do: for({k, v} <- pairs, not is_nil(v), into: %{}, do: {k, v})

  @doc """
  Parses `response_type` (§3.1.1). Extension response types may hold several
  space-delimited names whose order does not matter, so the result is a `MapSet`.

      iex> Oat.OAuth2.Params.response_type("token code")
      {:ok, MapSet.new(["code", "token"])}
  """
  @spec response_type(String.t()) :: {:ok, MapSet.t(String.t())} | {:error, :invalid_request}
  def response_type(value) do
    if Oat.OAuth2.Syntax.response_type?(value) do
      {:ok, value |> String.split(" ") |> MapSet.new()}
    else
      {:error, :invalid_request}
    end
  end
end
