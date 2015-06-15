package com.yuaoq.ofbiz.cas.adaptors.jdbc;

import com.yuaoq.ofbiz.base.crypto.HashCrypt;
import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.principal.SimplePrincipal;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;
import java.security.GeneralSecurityException;

/**
 * Created by tusm on 15/5/27.
 */
public class OfbizQueryDataBaseAuthHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {


    @NotNull
    private String sql;
    @NotNull
    private  String crypt;


    /** {@inheritDoc} */
    @Override
    protected  HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential)
            throws GeneralSecurityException, PreventedException {

        final String username = credential.getUsername();
        final String password = credential.getPassword();
        try {
            final String dbPassword = getJdbcTemplate().queryForObject(this.sql, String.class, username);
            if(!HashCrypt.comparePassword(dbPassword, crypt, password)){
                throw new FailedLoginException("Password does not match value on record.");
            }
        } catch (final IncorrectResultSizeDataAccessException e) {
            if (e.getActualSize() == 0) {
                throw new AccountNotFoundException(username + " not found with SQL query");
            } else {
                throw new FailedLoginException("Multiple records found for " + username);
            }
        } catch (final DataAccessException e) {
            throw new PreventedException("SQL exception while executing query for " + username, e);
        }
        return createHandlerResult(credential, new SimplePrincipal(username), null);
    }

    /**
     * @param sql The sql to set.
     */
    public  void setSql( String sql) {
        this.sql = sql;
    }

    public  String getCrypt() {
        return crypt;
    }

    public  void setCrypt(  String crypt) {
        this.crypt = crypt;
    }
}
