<?php

class ChangePasswordPostfixAdminDriver implements \RainLoop\Providers\ChangePassword\ChangePasswordInterface
{
	/**
	 * @var string
	 */
	private $sDriver = 'mysql';

	/**
	 * @var string
	 */
	private $sHost = 'localhost';

	/**
	 * @var int
	 */
	private $iPort = 3306;

	/**
	 * @var string
	 */
	private $sDatabase = 'postfixadmin';

	/**
	* @var string
	*/
	private $sTable = 'mailbox';

	/**
	* @var string
	*/
	private $sUsercol = 'username';

	/**
	* @var string
	*/
	private $sPasscol = 'password';

	/**
	 * @var string
	 */
	private $sUser = 'postfixadmin';

	/**
	 * @var string
	 */
	private $sPassword = '';

	/**
	 * @var string
	 */
	private $sEncrypt = '';

	/**
	 * @var string
	 */
	private $sAllowedEmails = '';

	/**
	 * @var \MailSo\Log\Logger
	 */
	private $oLogger = null;

	/**
	 * @param string $sDriver
	 *
	 * @return \ChangePasswordPostfixAdminDriver
	 */
	public function SetDriver($sDriver)
	{
		$this->sDriver = $sDriver;
		return $this;
	}

	/**
	 * @param string $sHost
	 *
	 * @return \ChangePasswordPostfixAdminDriver
	 */
	public function SetHost($sHost)
	{
		$this->sHost = $sHost;
		return $this;
	}

	/**
	 * @param int $iPort
	 *
	 * @return \ChangePasswordPostfixAdminDriver
	 */
	public function SetPort($iPort)
	{
		$this->iPort = (int) $iPort;
		return $this;
	}

	/**
	 * @param string $sDatabase
	 *
	 * @return \ChangePasswordPostfixAdminDriver
	 */
	public function SetDatabase($sDatabase)
	{
		$this->sDatabase = $sDatabase;
		return $this;
	}

	/**
	* @param string $sTable
	*
	* @return \ChangePasswordPostfixAdminDriver
	*/
	public function SetTable($sTable)
	{
		$this->sTable = $sTable;
		return $this;
	}

	/**
	* @param string $sUsercol
	*
	* @return \ChangePasswordPostfixAdminDriver
	*/
	public function SetUserColumn($sUsercol)
	{
		$this->sUsercol = $sUsercol;
		return $this;
	}

	/**
	* @param string $sPasscol
	*
	* @return \ChangePasswordPostfixAdminDriver
	*/
	public function SetPasswordColumn($sPasscol)
	{
		$this->sPasscol = $sPasscol;
		return $this;
	}

	/**
	 * @param string $sUser
	 *
	 * @return \ChangePasswordPostfixAdminDriver
	 */
	public function SetUser($sUser)
	{
		$this->sUser = $sUser;
		return $this;
	}

	/**
	 * @param string $sPassword
	 *
	 * @return \ChangePasswordPostfixAdminDriver
	 */
	public function SetPassword($sPassword)
	{
		$this->sPassword = $sPassword;
		return $this;
	}

	/**
	 * @param string $sEncrypt
	 *
	 * @return \ChangePasswordPostfixAdminDriver
	 */
	public function SetEncrypt($sEncrypt)
	{
		$this->sEncrypt = $sEncrypt;
		return $this;
	}

	/**
	 * @param string $sAllowedEmails
	 *
	 * @return \ChangePasswordPostfixAdminDriver
	 */
	public function SetAllowedEmails($sAllowedEmails)
	{
		$this->sAllowedEmails = $sAllowedEmails;
		return $this;
	}

	/**
	 * @param \MailSo\Log\Logger $oLogger
	 *
	 * @return \ChangePasswordPostfixAdminDriver
	 */
	public function SetLogger($oLogger)
	{
		if ($oLogger instanceof \MailSo\Log\Logger)
		{
			$this->oLogger = $oLogger;
		}

		return $this;
	}

	/**
	 * @param \RainLoop\Model\Account $oAccount
	 *
	 * @return bool
	 */
	public function PasswordChangePossibility($oAccount)
	{
		return $oAccount && $oAccount->Email() &&
			\RainLoop\Plugins\Helper::ValidateWildcardValues($oAccount->Email(), $this->sAllowedEmails);
	}

	/**
	 * @param \RainLoop\Model\Account $oAccount
	 * @param string $sPrevPassword
	 * @param string $sNewPassword
	 *
	 * @return bool
	 */
	public function ChangePassword(\RainLoop\Account $oAccount, $sPrevPassword, $sNewPassword)
	{
		if ($this->oLogger)
		{
			$this->oLogger->Write('Postfix: Try to change password for '.$oAccount->Email());
		}

		unset($sPrevPassword);

		$bResult = false;

		if (0 < \strlen($sNewPassword))
		{
			try
			{
				$sDsn = $this->sDriver.':host='.$this->sHost.';port='.$this->iPort.';dbname='.$this->sDatabase;

				$oPdo = new \PDO($sDsn, $this->sUser, $this->sPassword);
				$oPdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

				$sUpdatePassword = $this->cryptPassword($sNewPassword, $oPdo);
				if (0 < \strlen($sUpdatePassword))
				{
					$oStmt = $oPdo->prepare("UPDATE {$this->sTable} SET {$this->sPasscol} = ? WHERE {$this->sUsercol} = ?");
					$bResult = (bool) $oStmt->execute(array($sUpdatePassword, $oAccount->Email()));
				}
				else
				{
					if ($this->oLogger)
					{
						$this->oLogger->Write('Postfix: Encrypted password is empty',
							\MailSo\Log\Enumerations\Type::ERROR);
					}
				}

				$oPdo = null;
			}
			catch (\Exception $oException)
			{
				if ($this->oLogger)
				{
					$this->oLogger->WriteException($oException);
				}
			}
		}

		return $bResult;
	}

	/**
	 * @param int $iLength
	 * @param string $keySpace
	 *
	 * @return string
	 */
	private function randomSalt($length, $keyspace = './0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
	{
		$str = '';
		$max = mb_strlen($keyspace, '8bit') - 1;
		for ($i = 0; $i < $length; ++$i) {
			$str .= $keyspace[random_int(0, $max)];
		}
		return $str;
	}

	/**
	 * @param string $sPassword
	 * @param \PDO $oPdo
	 *
	 * @return string
	 */
	private function cryptPassword($sPassword, $oPdo)
	{
		$sResult = '';
		$sSalt = '';
		switch (strtolower($this->sEncrypt))
		{
			default:
			case 'clear':
			case 'cleartext':
			case 'plain':
				$sResult = '{PLAIN}' . $sPassword;
				break;

			case 'plain-md5':
				$sResult = '{PLAIN-MD5}' . md5($sPassword);
				break;

			case 'crypt':
				$sResult = '{CRYPT}' . crypt($sPassword);
				break;

			case 'md5-crypt':
				$sSalt = $this->randomSalt(8);
				$sResult = '{MD5-CRYPT}' . crypt($sPassword, '$1$'.$sSalt);
				break;

			case 'sha256':
				$sResult = '{SHA256}' . base64_encode(hash('sha256', $sPassword, true));
				break;

			case 'sha256-crypt':
				$sSalt = $this->randomSalt(16);
				$sResult = '{SHA256-CRYPT}' . crypt($sPassword, '$5$'.$sSalt);
				break;

			case 'ssha256':
				$sSalt = $this->randomSalt(16);
				$sResult = '{SSHA256}' . base64_encode(hash('sha256', $sPassword . $sSalt, true) . $sSalt);
				break;

			case 'sha512':
				$sResult = '{SHA512}' . base64_encode(hash('sha512', $sPassword, true));
				break;

			case 'sha512-crypt':
				$sSalt = $this->randomSalt(16);
				$sResult = '{SHA512-CRYPT}' . crypt($sPassword, '$6$'.$sSalt);
				break;

			case 'ssha512':
				$sSalt = $this->randomSalt(16);
				$sResult = '{SSHA512}' . base64_encode(hash('sha512', $sPassword . $sSalt, true) . $sSalt);
				break;

			case 'blf-crypt':
				$sSalt = $this->randomSalt(22);
				$sResult = '{BLF-CRYPT}' . crypt($sPassword, '$2y$05$'.$sSalt);
				break;
		}

		return $sResult;
	}
}
