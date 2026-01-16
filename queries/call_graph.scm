;; ---- direct calls: foo(...) ----
(
  call_expression
    function: (identifier) @call.name
)

;; ---- member calls: obj->foo(...) / obj.foo(...) ----
(
  call_expression
    function: (field_expression
      field: (field_identifier) @call.name
    )
)
