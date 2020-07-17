package io.gaia_app.credentials

import io.gaia_app.encryption.EncryptionService
import io.gaia_app.teams.User
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.util.*

@Service
class CredentialsService(val credentialsRepository: CredentialsRepository){

    @Autowired(required = false)
    var encryptionService: EncryptionService? = null

    fun findById(id: String): Optional<Credentials> = this.credentialsRepository.findById(id).map { decrypt(it) }

    fun findByIdAndCreatedBy(id: String, createdBy: User): Optional<Credentials> = credentialsRepository.findByIdAndCreatedBy(id, createdBy).map { decrypt(it) }

    fun findAllByCreatedBy(createdBy: User) = credentialsRepository.findAllByCreatedBy(createdBy)

    fun save(credentials: Credentials): Credentials {
        return encrypt(credentials).apply { credentialsRepository.save(credentials) }
    }

    fun deleteById(id:String) = credentialsRepository.deleteById(id)

    fun encrypt(it: Credentials): Credentials {
        return when(it) {
            is AWSCredentials -> encryptionService?.encrypt(it) ?: it
            else -> it
        }
    }

    fun decrypt(it: Credentials): Credentials {
        return when(it) {
            is AWSCredentials -> encryptionService?.decrypt(it) ?: it
            else -> it
        }
    }
}

fun EncryptionService.decrypt(awsCredentials: AWSCredentials): AWSCredentials {
    val (accessKey, secretKey) = this.decryptBatch(listOf(awsCredentials.accessKey, awsCredentials.secretKey))
    return AWSCredentials(accessKey, secretKey)
}

fun EncryptionService.encrypt(awsCredentials: AWSCredentials): AWSCredentials {
    val (accessKey, secretKey) = this.encryptBatch(listOf(awsCredentials.accessKey, awsCredentials.secretKey))
    return AWSCredentials(accessKey, secretKey)
}
