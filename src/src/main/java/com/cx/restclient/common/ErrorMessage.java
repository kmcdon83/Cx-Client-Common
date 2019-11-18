package com.cx.restclient.common;

public enum ErrorMessage  {
	INTERNAL_ERROR("INTERNAL_ERROR: %s"),
	INVALID_INPUT("INVALID_INPUT"),
	FORBIDDEN("FORBIDDEN"), //forbidden request such remove primary user
	NOT_FOUND("NOT_FOUND"), //The given entity does not exist
	NOT_FOUND_WITH_REQUEST_PARAM("Resource not found for requested params %s"), //The given entity does not exist
	ALREADY_EXISTS("ALREADY_EXISTS"), //The given entity already exists
	NOT_AUTHORIZED("NOT_AUTHORIZED"),
	PROPERTY_NOT_FOUND("PROPERTY_NOT_FOUND"),
	PATH_PARAM_IS_MANDATORY("The [%s] path marameter is mandatory"),
	SERVICE_UNAVAILABLE("Server is unavailable"),
	CHECKMARX_SERVER_CONNECTION_FAILED("Connection failed. Please recheck the hostname and credentials you provided and try again.");

	private String errorMessage;

	private ErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	public String getErrorMessage() {
		return errorMessage;
	}
	
	public String formatError(Object... args) {
		return String.format(errorMessage, args);
	}
}
