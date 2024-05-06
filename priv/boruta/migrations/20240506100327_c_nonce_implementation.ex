defmodule Boruta.Migrations.CNonceImplementation do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20240506073706_add_c_nonce_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :c_nonce, :string
        end
      end
    end
  end
end

