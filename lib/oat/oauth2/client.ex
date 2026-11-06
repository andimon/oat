defmodule Oat.OAuth2.Client do
  @moduledoc """
  A registered client: RFC 6749 §2 (https://www.rfc-editor.org/rfc/rfc6749#section-2).

  The primary key is the client identifier (§2.2). A client with a secret is
  confidential and must authenticate at the token endpoint; a client without
  one is public (§2.1).
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Oat.OAuth2.{RedirectURI, Syntax}

  @type t :: %__MODULE__{}

  # Authorization response parameters (§4.1.2, §4.1.2.1). They are added to the
  # redirect URI's query, and must not appear in it twice (§3.1).
  @response_params ~w(code state error error_description error_uri)

  @primary_key {:id, :string, autogenerate: false}

  schema "oauth_clients" do
    field :name, :string
    field :secret_hash, :string, redact: true
    field :redirect_uris, {:array, :string}, default: []
    field :scopes, {:array, :string}, default: []
    field :default_scopes, {:array, :string}, default: []

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(client, attrs) do
    client
    |> cast(attrs, [:id, :name, :secret_hash, :redirect_uris, :scopes, :default_scopes])
    |> validate_required([:id, :name])
    |> validate_change(:id, fn :id, id ->
      if Syntax.client_id?(id), do: [], else: [id: "must be printable ASCII"]
    end)
    |> validate_redirect_uris_present()
    |> validate_change(:redirect_uris, fn :redirect_uris, uris ->
      cond do
        not Enum.all?(uris, &RedirectURI.valid?/1) ->
          [redirect_uris: "must be absolute URIs without a fragment"]

        Enum.any?(uris, &has_response_params?/1) ->
          [redirect_uris: "must not include the #{Enum.join(@response_params, ", ")} parameters"]

        true ->
          []
      end
    end)
    |> validate_change(:scopes, &validate_scope_tokens/2)
    |> validate_change(:default_scopes, &validate_scope_tokens/2)
    |> validate_default_scopes()
    |> unique_constraint(:id, name: :oauth_clients_pkey)
  end

  @doc "Whether the client is confidential, i.e. has a secret (§2.1)."
  def confidential?(%__MODULE__{secret_hash: hash}), do: is_binary(hash)

  defp has_response_params?(uri) do
    query = URI.parse(uri).query || ""
    query |> URI.query_decoder(:www_form) |> Enum.any?(fn {k, _} -> k in @response_params end)
  end

  defp validate_scope_tokens(field, tokens) do
    if Enum.all?(tokens, &Syntax.scope_token?/1),
      do: [],
      else: [{field, "must be valid scope tokens"}]
  end

  # A client must register at least one redirection URI (§3.1.2.2). The empty
  # list is the default, so it is not a change and validate_length/3 skips it.
  defp validate_redirect_uris_present(changeset) do
    case get_field(changeset, :redirect_uris) do
      [_ | _] -> changeset
      _ -> add_error(changeset, :redirect_uris, "must have at least one URI")
    end
  end

  defp validate_default_scopes(changeset) do
    scopes = get_field(changeset, :scopes)

    validate_change(changeset, :default_scopes, fn :default_scopes, defaults ->
      if Enum.all?(defaults, &(&1 in scopes)),
        do: [],
        else: [default_scopes: "must be a subset of scopes"]
    end)
  end
end
