package app.pbac

import rego.v1

default allow := false

allow if {
	user_is_admin
}

allow if {
	user_is_employee
	user_belongs_toip
	action_is_read
}

allow if {
	user_is_employee
	user_belongs_toip
	action_is_write
}

allow if {
	user_is_customer
	user_belongs_toip
	action_is_read
}

user_is_admin if data.user_attributes[input.user].role == "admin"

user_is_employee if data.user_attributes[input.user].role == "employee"

user_is_customer if data.user_attributes[input.user].role == "customer"

user_belongs_toip if {
	data.ip_assignment[input.user][_].ip == input.ip
}

action_is_read if input.action == "read"

action_is_write if input.action == "write"

action_is_delete if input.action == "delete"
