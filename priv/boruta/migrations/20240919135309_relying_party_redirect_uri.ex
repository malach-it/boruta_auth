defmodule Boruta.Migrations.RelyingPartyRedirectUri do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20240919113816_add_relying_party_redirect_uri_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :relying_party_redirect_uri, :string
        end
      end
    end
  end
end
