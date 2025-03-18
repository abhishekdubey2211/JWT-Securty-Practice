package com.abhi.security.model;

public enum Role {
    SUPERADMIN(1),
    ADMIN(2),
    MODERATOR(3),
    USER(4);

    private final int roleId;

    Role(int roleId) {
        this.roleId = roleId;
    }

    public int getRoleId() {
        return roleId;
    }
}