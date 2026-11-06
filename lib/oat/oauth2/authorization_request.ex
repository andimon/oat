defmodule Oat.OAuth2.AuthorizationRequest do
  @moduledoc """
  A validated authorization request (RFC 6749 §4.1.1), waiting for the
  resource owner's decision.

    * `redirect_uri` is where the response goes: the requested URI, or the
      client's only registered one when the request left it out.
    * `redirect_uri_param?` records whether the request included
      `redirect_uri`, because the token request must then repeat it (§4.1.3).
    * `requested_scopes` is what the client asked for; `scopes` is what will
      be granted, after defaults are applied (§3.3).
  """

  @enforce_keys [:client, :redirect_uri, :redirect_uri_param?, :scopes, :requested_scopes]
  defstruct [:client, :redirect_uri, :redirect_uri_param?, :scopes, :requested_scopes, :state]

  @type t :: %__MODULE__{
          client: Oat.OAuth2.Client.t(),
          redirect_uri: String.t(),
          redirect_uri_param?: boolean(),
          scopes: Oat.OAuth2.Scope.t(),
          requested_scopes: Oat.OAuth2.Scope.t(),
          state: String.t() | nil
        }
end
