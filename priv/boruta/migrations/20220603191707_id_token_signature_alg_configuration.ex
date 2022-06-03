defmodule Boruta.Migrations.IdTokenSignatureAlgConfiguration do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20220603163123_add_id_token_signature_alg_to_clients.exs
        alter table(:oauth_clients) do
          add :id_token_signature_alg, :string, default: "RS512"
        end
      end
    end
  end
end
