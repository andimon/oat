defmodule Oat.OAuth2.Error do
  @moduledoc """
  OAuth 2.0 error responses (RFC 6749 §4.1.2.1, §5.2).

  The same struct serves both endpoints:

  * Authorization endpoint errors go back to the client as redirect parameters
    (`to_params/1` with `Oat.OAuth2.RedirectURI.append/2`), with `state` copied
    from the request.
  * Token endpoint errors are a JSON body (`to_params/1`) with the status from
    `status/1`.
  """

  alias Oat.OAuth2.Syntax

  @authorization_codes ~w(invalid_request unauthorized_client access_denied unsupported_response_type
                          invalid_scope server_error temporarily_unavailable)a
  @token_codes ~w(invalid_request invalid_client invalid_grant unauthorized_client
                  unsupported_grant_type invalid_scope)a

  @enforce_keys [:error]
  defstruct [:error, :description, :uri, :state]

  @type code :: atom()
  @type t :: %__MODULE__{
          error: code(),
          description: String.t() | nil,
          uri: String.t() | nil,
          state: String.t() | nil
        }

  @doc "Error codes defined for the authorization endpoint (§4.1.2.1)."
  def authorization_codes, do: @authorization_codes

  @doc "Error codes defined for the token endpoint (§5.2)."
  def token_codes, do: @token_codes

  @doc """
  Builds an error. Raises `ArgumentError` if the description or URI would break
  the character set rules (§4.1.2.1, Appendix A.8, A.9), since those values come
  from server code rather than from the client.

  Options: `:description`, `:uri`, `:state`.
  """
  @spec new(code(), keyword()) :: t()
  def new(code, opts \\ []) when is_atom(code) do
    error = struct!(__MODULE__, [error: code] ++ Keyword.take(opts, [:description, :uri, :state]))

    unless Syntax.error?(Atom.to_string(code)),
      do: raise(ArgumentError, "invalid error code #{inspect(code)}")

    if error.description && not Syntax.error_description?(error.description),
      do: raise(ArgumentError, "error description must be printable ASCII without \" or \\")

    if error.uri && not Syntax.uri_reference?(error.uri),
      do: raise(ArgumentError, "error uri must be a URI reference")

    error
  end

  @doc """
  The response parameters, leaving out `nil` values. Use as a JSON body at the
  token endpoint, or as redirect parameters at the authorization endpoint.
  """
  @spec to_params(t()) :: %{String.t() => String.t()}
  def to_params(%__MODULE__{} = error) do
    [
      {"error", Atom.to_string(error.error)},
      {"error_description", error.description},
      {"error_uri", error.uri},
      {"state", error.state}
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
    |> Map.new()
  end

  @doc """
  HTTP status for a token endpoint error (§5.2). `invalid_client` is 401 when
  the client authenticated with the `Authorization` header, and otherwise may be
  400 or 401; pass `header_auth?: true` when the header was used.
  """
  @spec status(t(), keyword()) :: 400 | 401
  def status(error, opts \\ [])

  def status(%__MODULE__{error: :invalid_client}, opts),
    do: if(opts[:header_auth?], do: 401, else: 400)

  def status(%__MODULE__{}, _opts), do: 400
end
