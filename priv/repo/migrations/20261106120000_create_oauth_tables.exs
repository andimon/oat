defmodule Oat.Repo.Migrations.CreateOauthTables do
  use Ecto.Migration

  def change do
    # The primary key is the client identifier issued to the client (RFC 6749 §2.2).
    create table(:oauth_clients, primary_key: false) do
      add :id, :string, primary_key: true
      add :name, :string, null: false
      # SHA-256 of the client secret; NULL for public clients (§2.1).
      add :secret_hash, :string
      add :redirect_uris, {:array, :string}, null: false, default: []
      add :scopes, {:array, :string}, null: false, default: []
      add :default_scopes, {:array, :string}, null: false, default: []

      timestamps(type: :utc_datetime)
    end

    create table(:oauth_authorization_codes) do
      add :code_hash, :string, null: false

      add :client_id, references(:oauth_clients, type: :string, on_delete: :delete_all),
        null: false

      add :resource_owner_id, :string, null: false
      # Set only when the authorization request included redirect_uri (§4.1.3).
      add :redirect_uri, :string
      add :scopes, {:array, :string}, null: false
      add :requested_scopes, {:array, :string}, null: false
      add :expires_at, :utc_datetime, null: false
      add :redeemed_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:oauth_authorization_codes, [:code_hash])

    create table(:oauth_access_tokens) do
      add :token_hash, :string, null: false

      add :client_id, references(:oauth_clients, type: :string, on_delete: :delete_all),
        null: false

      add :authorization_code_id,
          references(:oauth_authorization_codes, on_delete: :nilify_all)

      add :resource_owner_id, :string, null: false
      add :scopes, {:array, :string}, null: false
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:oauth_access_tokens, [:token_hash])
    create index(:oauth_access_tokens, [:authorization_code_id])
  end
end
