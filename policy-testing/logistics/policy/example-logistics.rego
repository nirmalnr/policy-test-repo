package logistics

import rego.v1

default result := {
  "valid": true,
  "violations": []
}

result := {
  "valid": count(violations) == 0,
  "violations": violations
}

violations contains "confirm: missing provider in order" if {
    input.context.action == "confirm"
    not input.message.order.provider
}

violations contains "confirm: missing payment info" if {
    input.context.action == "confirm"
    not input.message.order.payment
}

violations contains "confirm: missing delivery fulfillment type" if {
    input.context.action == "confirm"
    some f in input.message.order.fulfillments
    not f.type
}

violations contains "confirm: vehicle category required for logistics network" if {
    input.context.action == "confirm"
    not input.message.order.tags.vehicle_category
}
