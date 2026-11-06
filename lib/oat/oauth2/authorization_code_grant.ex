defmodule Oat.OAuth2.AuthorizationCodeGrant do
  @moduledoc """
  The authorization code grant (RFC 6749 §4.1).

      +----------+
      | Resource |
      |   Owner  |
      +----------+
           ^
           |
          (B)
      +----|-----+          Client Identifier      +---------------+
      |         -+----(A)-- & Redirection URI ---->|               |
      |  User-   |                                 | Authorization |
      |  Agent  -+----(B)-- User authenticates --->|     Server    |
      |          |                                 |               |
      |         -+----(C)-- Authorization Code ---<|               |
      +-|----|---+                                 +---------------+
        |    |                                         ^      v
       (A)  (C)                                        |      |
        |    |                                         |      |
        ^    v                                         |      |
      +---------+                                      |      |
      |         |>---(D)-- Authorization Code ---------'      |
      |  Client |          & Redirection URI                  |
      |         |                                             |
      |         |<---(E)----- Access Token -------------------'
      +---------+       (w/ Optional Refresh Token)

  * `validate/1` checks the authorization request from step (A).
  * `approve/2` and `deny/1` produce the redirect for step (C), once the
    resource owner has decided in step (B).
  * `exchange/2` handles the token request from step (D) and returns the
    token response for step (E).

  Lifetimes, in seconds, can be set with:

      config :oat, Oat.OAuth2.AuthorizationCodeGrant,
        authorization_code_lifetime: 600,
        access_token_lifetime: 3600

  Refresh tokens are not issued yet.
  """

  import Ecto.Query

  alias Oat.OAuth2.{
    AccessToken,
    AuthorizationCode,
    AuthorizationRequest,
    Client,
    Clients,
    Error,
    Params,
    RedirectURI,
    Scope,
    Syntax,
    Token,
    TokenResponse
  }

  alias Oat.Repo

  # §4.1.2 recommends 10 minutes at most.
  @default_code_lifetime 600
  @default_token_lifetime 3600

  @doc """
  Validates an authorization request (§4.1.1) from its raw query string.

  Returns:

    * `{:ok, request}` when the request is valid and the resource owner can be
      asked for a decision.
    * `{:error, :redirect, uri}` when the client and redirection URI are valid
      but the request is not. `uri` carries the error parameters (§4.1.2.1).
    * `{:error, :show, error}` when the client or redirection URI is missing or
      invalid. The server must not redirect; show `error` to the resource
      owner instead (§4.1.2.1, §10.15).
  """
  @spec validate(String.t() | nil) ::
          {:ok, AuthorizationRequest.t()}
          | {:error, :redirect, String.t()}
          | {:error, :show, Error.t()}
  def validate(query) do
    {params, repeated} =
      case Params.decode(query) do
        {:ok, params} -> {params, nil}
        {:error, {:repeated, name}, params} -> {params, name}
      end

    with {:ok, client} <- fetch_client(params, repeated),
         {:ok, redirect_uri} <- fetch_redirect_uri(client, params, repeated) do
      state = if Syntax.state?(params["state"]), do: params["state"]

      case validate_rest(params, repeated, client) do
        {:ok, requested, scopes} ->
          {:ok,
           %AuthorizationRequest{
             client: client,
             redirect_uri: redirect_uri,
             redirect_uri_param?: Map.has_key?(params, "redirect_uri"),
             requested_scopes: requested,
             scopes: scopes,
             state: state
           }}

        {:error, code, description} ->
          error = Error.new(code, description: description, state: state)
          {:error, :redirect, RedirectURI.append(redirect_uri, Error.to_params(error))}
      end
    end
  end

  defp fetch_client(params, repeated) do
    cond do
      repeated == "client_id" ->
        show(:invalid_request, "The client_id parameter is repeated")

      not Map.has_key?(params, "client_id") ->
        show(:invalid_request, "The client_id parameter is missing")

      client = Clients.get(params["client_id"]) ->
        {:ok, client}

      true ->
        show(:invalid_request, "Unknown client")
    end
  end

  defp fetch_redirect_uri(client, params, repeated) do
    if repeated == "redirect_uri" do
      show(:invalid_request, "The redirect_uri parameter is repeated")
    else
      case RedirectURI.resolve(params["redirect_uri"], client.redirect_uris) do
        {:ok, uri} -> {:ok, uri}
        {:error, :missing_redirect_uri} -> show(:invalid_request, "The redirect_uri is missing")
        {:error, :invalid_redirect_uri} -> show(:invalid_request, "The redirect_uri is invalid")
      end
    end
  end

  defp show(code, description), do: {:error, :show, Error.new(code, description: description)}

  defp validate_rest(params, repeated, %Client{} = client) do
    with :ok <- check_repeated(repeated),
         :ok <- check_state(params),
         :ok <- check_response_type(params),
         {:ok, requested} <- parse_scope(params["scope"]),
         {:ok, scopes} <- resolve_scope(requested, client) do
      {:ok, requested, scopes}
    end
  end

  defp check_repeated(nil), do: :ok

  defp check_repeated(name),
    do: {:error, :invalid_request, "The #{name} parameter is repeated"}

  defp check_state(%{"state" => state}) do
    if Syntax.state?(state),
      do: :ok,
      else: {:error, :invalid_request, "The state parameter is invalid"}
  end

  defp check_state(_params), do: :ok

  defp check_response_type(%{"response_type" => value}) do
    case Params.response_type(value) do
      {:ok, types} ->
        if MapSet.equal?(types, MapSet.new(["code"])),
          do: :ok,
          else: {:error, :unsupported_response_type, "Only the code response type is supported"}

      {:error, :invalid_request} ->
        {:error, :invalid_request, "The response_type parameter is invalid"}
    end
  end

  defp check_response_type(_params),
    do: {:error, :invalid_request, "The response_type parameter is missing"}

  defp parse_scope(value) do
    case Scope.parse(value) do
      {:ok, scope} -> {:ok, scope}
      {:error, :invalid_scope} -> {:error, :invalid_scope, "The scope parameter is invalid"}
    end
  end

  defp resolve_scope(requested, client) do
    case Scope.resolve(requested, MapSet.new(client.scopes), MapSet.new(client.default_scopes)) do
      {:ok, scope} -> {:ok, scope}
      {:error, :invalid_scope} -> {:error, :invalid_scope, "The requested scope is not allowed"}
    end
  end

  @doc """
  The resource owner approved the request: issues an authorization code and
  returns the redirect to send the user-agent to (§4.1.2).
  """
  @spec approve(AuthorizationRequest.t(), String.t()) :: {:ok, String.t()}
  def approve(%AuthorizationRequest{} = request, resource_owner_id)
      when is_binary(resource_owner_id) do
    code = Token.generate()
    now = DateTime.utc_now(:second)

    Repo.insert!(%AuthorizationCode{
      code_hash: Token.hash(code),
      client_id: request.client.id,
      resource_owner_id: resource_owner_id,
      redirect_uri: if(request.redirect_uri_param?, do: request.redirect_uri),
      scopes: Enum.sort(request.scopes),
      requested_scopes: Enum.sort(request.requested_scopes),
      expires_at: Token.expires_at(now, lifetime(:authorization_code_lifetime))
    })

    {:ok, RedirectURI.append(request.redirect_uri, code: code, state: request.state)}
  end

  @doc """
  The resource owner denied the request: returns the `access_denied` redirect
  (§4.1.2.1).
  """
  @spec deny(AuthorizationRequest.t()) :: String.t()
  def deny(%AuthorizationRequest{} = request) do
    error =
      Error.new(:access_denied,
        description: "The resource owner denied the request",
        state: request.state
      )

    RedirectURI.append(request.redirect_uri, Error.to_params(error))
  end

  @doc """
  Exchanges an authorization code for an access token (§4.1.3, §4.1.4).

  `client` is the client already authenticated by
  `Oat.OAuth2.Clients.authenticate/2`; `params` are the token request
  parameters.

  A code can be used once. If it is used again the request fails and every
  token issued from it is revoked (§4.1.2, §10.5).
  """
  @spec exchange(Client.t(), map()) :: {:ok, map()} | {:error, Error.t()}
  def exchange(%Client{} = client, params) do
    with {:ok, [code]} <- require_code(params) do
      result =
        Repo.transact(fn ->
          AuthorizationCode
          |> where(code_hash: ^Token.hash(code))
          |> lock("FOR UPDATE")
          |> Repo.one()
          |> redeem(client, params)
        end)

      case result do
        {:error, {:reused, code_id}} ->
          revoke_tokens_from(code_id)
          {:error, invalid_grant()}

        other ->
          other
      end
    end
  end

  defp require_code(params) do
    case Params.require(params, ["code"]) do
      {:ok, values} ->
        {:ok, values}

      {:error, {:missing, _}} ->
        {:error, Error.new(:invalid_request, description: "The code parameter is missing")}
    end
  end

  defp redeem(nil, _client, _params), do: {:error, invalid_grant()}

  defp redeem(%AuthorizationCode{redeemed_at: %DateTime{}} = code, _client, _params),
    do: {:error, {:reused, code.id}}

  defp redeem(%AuthorizationCode{} = code, client, params) do
    now = DateTime.utc_now(:second)

    cond do
      code.client_id != client.id ->
        {:error, invalid_grant()}

      Token.expired?(code.expires_at, now) ->
        {:error, invalid_grant()}

      code.redirect_uri && params["redirect_uri"] != code.redirect_uri ->
        {:error, invalid_grant()}

      true ->
        issue_token(code, now)
    end
  end

  defp issue_token(code, now) do
    code |> Ecto.Changeset.change(redeemed_at: now) |> Repo.update!()

    token = Token.generate()
    expires_at = Token.expires_at(now, lifetime(:access_token_lifetime))

    Repo.insert!(%AccessToken{
      token_hash: Token.hash(token),
      client_id: code.client_id,
      authorization_code_id: code.id,
      resource_owner_id: code.resource_owner_id,
      scopes: code.scopes,
      expires_at: expires_at
    })

    {:ok,
     TokenResponse.build(
       access_token: token,
       expires_in: Token.expires_in(expires_at, now),
       scope: MapSet.new(code.scopes),
       requested_scope: MapSet.new(code.requested_scopes)
     )}
  end

  defp revoke_tokens_from(code_id) do
    AccessToken
    |> where(authorization_code_id: ^code_id)
    |> where([t], is_nil(t.revoked_at))
    |> Repo.update_all(set: [revoked_at: DateTime.utc_now(:second)])
  end

  defp invalid_grant,
    do: Error.new(:invalid_grant, description: "The authorization code is invalid")

  defp lifetime(:authorization_code_lifetime = key),
    do: config(key, @default_code_lifetime)

  defp lifetime(:access_token_lifetime = key),
    do: config(key, @default_token_lifetime)

  defp config(key, default),
    do: :oat |> Application.get_env(__MODULE__, []) |> Keyword.get(key, default)
end
