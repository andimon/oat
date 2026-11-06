defmodule Oat.OAuth2.AuthorizationRequest do
  @moduledoc """
  A validated authorization request, RFC 6749 §4.1.1
  (https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1), waiting for the
  resource owner's decision.

    * `redirect_uri` is where the response goes: the requested URI, or the
      client's only registered one when the request left it out.
    * `bound_redirect_uri` is the `redirect_uri` parameter as sent, or `nil`
      when the request left it out. The code is bound to it, and the token
      request must then repeat it (§4.1.3).
    * `requested_scopes` is what the client asked for; `scopes` is what will
      be granted, after defaults are applied (§3.3).
  """

  @enforce_keys [:client, :redirect_uri]
  defstruct [
    :client,
    :redirect_uri,
    :bound_redirect_uri,
    :state,
    scopes: MapSet.new(),
    requested_scopes: MapSet.new()
  ]

  @type t :: %__MODULE__{
          client: Oat.OAuth2.Client.t(),
          redirect_uri: String.t(),
          bound_redirect_uri: String.t() | nil,
          scopes: Oat.OAuth2.Scope.t(),
          requested_scopes: Oat.OAuth2.Scope.t(),
          state: String.t() | nil
        }
end
