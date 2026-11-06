defmodule Oat.OAuth2.AuthorizationCode do
  @moduledoc """
  An authorization code issued by the authorization endpoint: RFC 6749 §4.1.2
  (https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2).

  Only the hash of the code is stored. A code is bound to the client, the
  resource owner, the granted scope and, when the authorization request
  included one, the `redirect_uri` (§4.1.3). `redeemed_at` is set the first
  time the code is exchanged; codes are single use.
  """

  use Ecto.Schema

  schema "oauth_authorization_codes" do
    field :code_hash, :string, redact: true
    field :resource_owner_id, :string
    field :redirect_uri, :string
    field :scopes, {:array, :string}
    field :requested_scopes, {:array, :string}
    field :expires_at, :utc_datetime
    field :redeemed_at, :utc_datetime

    belongs_to :client, Oat.OAuth2.Client, type: :string

    timestamps(type: :utc_datetime)
  end
end
