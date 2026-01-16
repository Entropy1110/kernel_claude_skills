;; ---- function definitions (common shapes) ----
(
  function_definition
    declarator: (function_declarator
      declarator: (identifier) @name
    )
) @definition.function

(
  function_definition
    declarator: (pointer_declarator
      declarator: (function_declarator
        declarator: (identifier) @name
      )
    )
) @definition.function

;; ---- direct calls: foo(...) ----
(
  call_expression
    function: (identifier) @name
) @reference.call

;; ---- member calls: obj->foo(...) / obj.foo(...) ----
(
  call_expression
    function: (field_expression
      field: (field_identifier) @name
    )
) @reference.call
