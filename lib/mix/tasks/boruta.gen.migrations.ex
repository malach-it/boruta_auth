defmodule Mix.Tasks.Boruta.Gen.Migration do
  @moduledoc """
  Migration task for Boruta.

  Creates `clients`, `scopes` and `tokens` tables.

  ## Examples
  ```
  mix boruta.gen.migration
  ```
  """

  use Mix.Task

  import Mix.Generator
  import Mix.Ecto
  import Mix.EctoSQL

  @shortdoc "Generates Boruta migrations"

  @doc false
  def run(args) do
    no_umbrella!("boruta.gen.migration")
    repos = parse_repo(args)

    Enum.map repos, fn repo ->
      ensure_repo(repo, args)

      path = Path.join(source_repo_priv(repo), "migrations")
      file = Path.join(path, "#{timestamp()}_create_boruta.exs")
      assigns = [
        mod: Module.concat([repo, Migrations, "CreateBoruta"])
      ]

      fuzzy_path = Path.join(path, "*_create_boruta.exs")
      if Path.wildcard(fuzzy_path) != [] do
        Mix.raise "migration can't be created, there is already a migration file with name create_boruta."
      end

      create_file file, migration_template(assigns)
    end
  end

  defp timestamp do
    {{y, m, d}, {hh, mm, ss}} = :calendar.universal_time()
    "#{y}#{pad(m)}#{pad(d)}#{pad(hh)}#{pad(mm)}#{pad(ss)}"
  end

  defp pad(i) when i < 10, do: << ?0, ?0 + i >>
  defp pad(i), do: to_string(i)

  defp migration_module do
    case Application.get_env(:ecto_sql, :migration_module, Ecto.Migration) do
      migration_module when is_atom(migration_module) -> migration_module
      other -> Mix.raise "Expected :migration_module to be a module, got: #{inspect(other)}"
    end
  end

  embed_template :migration, """
  defmodule <%= inspect @mod %> do
    use <%= inspect migration_module() %>

    def change do
      create table(:clients, primary_key: false) do
        add(:id, :uuid, primary_key: true)
        add(:name, :string, default: "", null: false)
        add(:secret, :string, null: false)
        add(:redirect_uris, {:array, :string}, default: [], null: false)
        add(:scope, :string)
        add(:authorize_scope, :boolean, default: false, null: false)
        add(:supported_grant_types, {:array, :string}, default: [], null: false)
        add(:authorization_code_ttl, :integer, null: false)
        add(:access_token_ttl, :integer, null: false)
        add(:pkce, :boolean, default: false, null: false)
        add(:public_key, :text, null: false)
        add(:private_key, :text, null: false)

        timestamps()
      end

      create table(:tokens, primary_key: false) do
        add(:id, :uuid, primary_key: true)
        add(:type, :string)
        add(:value, :string)
        add(:refresh_token, :string)
        add(:expires_at, :integer)
        add(:redirect_uri, :string)
        add(:state, :string)
        add(:scope, :string)
        add(:revoked_at, :utc_datetime_usec)
        add(:code_challenge_hash, :string)
        add(:code_challenge_method, :string)

        add(:client_id, references(:clients, type: :uuid, on_delete: :nilify_all))
        add(:sub, :string)

        timestamps(type: :utc_datetime_usec)
      end

      create table(:scopes, primary_key: false) do
        add :id, :binary_id, primary_key: true
        add :label, :string
        add :name, :string
        add :public, :boolean, default: false, null: false

        timestamps()
      end

      create table(:clients_scopes) do
        add(:client_id, references(:clients, type: :uuid, on_delete: :delete_all))
        add(:scope_id, references(:scopes, type: :uuid, on_delete: :delete_all))
      end

      create unique_index(:clients, [:id, :secret])
      create index("tokens", [:value])
      create unique_index("tokens", [:client_id, :value])
      create unique_index("tokens", [:client_id, :refresh_token])
      create unique_index("scopes", [:name])
    end
  end
  """
end
