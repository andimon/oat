defmodule Oat.OAuth2.Params do
  @moduledoc """
  Request parameter rules shared by the authorization and token endpoints
  (RFC 6749 §3.1, §3.2).

  * Parameters sent without a value are treated as omitted.
  * Request and response parameters must not be included more than once.
  * Unrecognised parameters are ignored.

  Plug's parsers keep only the last value of a repeated parameter, so the
  repetition check has to run on the raw query string or form body.
  """

  @doc """
  Decodes an `application/x-www-form-urlencoded` string, drops empty values and
  rejects repeated parameter names.

  On a repeat the error also carries the parameters decoded so far, keeping the
  first value of each name. The authorization endpoint needs them to decide
  whether it may redirect the error back to the client (§4.1.2.1).

      iex> Oat.OAuth2.Params.decode("response_type=code&client_id=s6&state=")
      {:ok, %{"response_type" => "code", "client_id" => "s6"}}

      iex> Oat.OAuth2.Params.decode("client_id=s6&scope=a&scope=b")
      {:error, {:repeated, "scope"}, %{"client_id" => "s6", "scope" => "a"}}
  """
  @spec decode(String.t() | nil) ::
          {:ok, %{String.t() => String.t()}}
          | {:error, {:repeated, String.t()}, %{String.t() => String.t()}}
  def decode(nil), do: {:ok, %{}}

  def decode(raw) when is_binary(raw) do
    raw
    |> URI.query_decoder(:www_form)
    |> Enum.reject(fn {_, value} -> value == "" end)
    |> Enum.reduce({%{}, nil}, fn {name, value}, {params, repeated} ->
      if Map.has_key?(params, name) do
        {params, repeated || name}
      else
        {Map.put(params, name, value), repeated}
      end
    end)
    |> case do
      {params, nil} -> {:ok, params}
      {params, name} -> {:error, {:repeated, name}, params}
    end
  end

  @doc """
  Fetches the required parameters, in order. Returns the first missing name on failure.
  """
  @spec require(map(), [String.t()]) :: {:ok, [String.t()]} | {:error, {:missing, String.t()}}
  def require(params, names) do
    Enum.reduce_while(names, {:ok, []}, fn name, {:ok, acc} ->
      case params do
        %{^name => value} -> {:cont, {:ok, [value | acc]}}
        _ -> {:halt, {:error, {:missing, name}}}
      end
    end)
    |> case do
      {:ok, values} -> {:ok, Enum.reverse(values)}
      error -> error
    end
  end

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
