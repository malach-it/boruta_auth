defmodule Boruta.Openid.Json.Schema do
  @moduledoc false
  alias ExJsonSchema.Schema

  def credential do
    %{
      "type" => "object",
      "properties" => %{
        "format" => %{"type" => "string"},
        "doctype" => %{"type" => "string"},
        "proof" => %{
          "type" => "object",
          "properties" => %{
            "proof_type" => %{"type" => "string", "pattern" => "^jwt$"},
            "jwt" => %{"type" => "string"}
          },
          "required" => ["proof_type", "jwt"]
        },
        "credential_identifier" => %{"type" => "string"},
        "types" => %{
          "type" => "array",
          "items" => %{"type" => "string"}
        }
      },
      "required" => ["format", "proof"]
    }
    |> Schema.resolve()
  end

  def presentation_submission do
    %{
      "type" => "object",
      "properties" => %{
        "id" => %{"type" => "string"},
        "definition_id" => %{"type" => "string"},
        "descriptor_map" => %{
          "type" => "array",
          "items" => %{
            "type" => "object",
            "properties" => %{
              "id" => %{"type" => "string"},
              "format" => %{"type" => "string", "pattern" => "^jwt_vp$"},
              "path" => %{"type" => "string"},
              "path_nested" => %{
                "type" => "object",
                "properties" => %{
                  "id" => %{"type" => "string"},
                  "format" => %{"type" => "string", "pattern" => "^jwt_vc$"},
                  "path" => %{"type" => "string"}
                },
                "required" => ["id", "format", "path"]
              }
            },
            "required" => ["id", "format", "path", "path_nested"]
          }
        }
      },
      "required" => ["id", "descriptor_map"]
    }
  end
end
