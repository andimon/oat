defmodule Oat.OAuth2.AccessToken do
  @moduledoc """
  An access token issued by the token endpoint: RFC 6749 §1.4
  (https://www.rfc-editor.org/rfc/rfc6749#section-1.4).

  Only the hash of the token is stored. `authorization_code_id` records the
  code the token was issued from, so the token can be revoked if that code is
  used again (§4.1.2, §10.5).
  """

  use Ecto.Schema

  schema "oauth_access_tokens" do
    field :token_hash, :string, redact: true
    field :resource_owner_id, :string
    field :scopes, {:array, :string}
    field :expires_at, :utc_datetime
    field :revoked_at, :utc_datetime

    belongs_to :client, Oat.OAuth2.Client, type: :string
    belongs_to :authorization_code, Oat.OAuth2.AuthorizationCode

    timestamps(type: :utc_datetime)
  end
end
