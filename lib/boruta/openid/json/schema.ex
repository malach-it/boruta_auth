defmodule Boruta.Openid.Json.Schema do
  @moduledoc false
  alias ExJsonSchema.Schema

  def credential do
    %{
      "type" => "object",
      "properties" => %{
        "format" => %{"type" => "string"},
        "proof" => %{
          "type" => "object",
          "properties" => %{
            "proof_type" => %{"type" => "string", "pattern" => "^jwt$"},
            "jwt" => %{"type" => "string"},
          },
          "required" => ["proof_type", "jwt"]
        },
        "credential_identifier" => %{"type" => "string"},
      },
      "required" => ["credential_identifier"]
    }
    |> Schema.resolve()
  end
end
