<?php

class PostfixadminChangePasswordPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	public function Init()
	{
		$this->addHook('main.fabrica', 'MainFabrica');
	}

	/**
	 * @return string
	 */
	public function Supported()
	{
		if (!extension_loaded('pdo') || !class_exists('PDO'))
		{
			return 'The PHP extension PDO must be installed to use this plugin';
		}

		$aDrivers = \PDO::getAvailableDrivers();
		if (!is_array($aDrivers) || !in_array($this->Config()->Get('plugin', 'driver', 'mysql'), $aDrivers))
		{
			return 'The PHP extension PDO must be installed to use this plugin';
		}

		return '';
	}

	/**
	 * @param string $sName
	 * @param mixed $oProvider
	 */
	public function MainFabrica($sName, &$oProvider)
	{
		switch ($sName)
		{
			case 'change-password':

				include_once __DIR__.'/ChangePasswordPostfixAdminDriver.php';

				$oProvider = new ChangePasswordPostfixAdminDriver();

				$oProvider
					->SetDriver($this->Config()->Get('plugin', 'driver', ''))
					->SetHost($this->Config()->Get('plugin', 'host', ''))
					->SetPort((int) $this->Config()->Get('plugin', 'port', 3306))
					->SetDatabase($this->Config()->Get('plugin', 'database', ''))
					->SetTable($this->Config()->Get('plugin', 'table', ''))
					->SetUserColumn($this->Config()->Get('plugin', 'usercol', ''))
					->SetPasswordColumn($this->Config()->Get('plugin', 'passcol', ''))
					->SetUser($this->Config()->Get('plugin', 'user', ''))
					->SetPassword($this->Config()->Get('plugin', 'password', ''))
					->SetEncrypt($this->Config()->Get('plugin', 'encrypt', ''))
					->SetAllowedEmails(\strtolower(\trim($this->Config()->Get('plugin', 'allowed_emails', ''))))
					->SetLogger($this->Manager()->Actions()->Logger())
				;

				break;
		}
	}

	/**
	 * @return array
	 */
	public function configMapping()
	{
		return array(
			\RainLoop\Plugins\Property::NewInstance('driver')->SetLabel('Database Driver')
				->SetDefaultValue('mysql'),
			\RainLoop\Plugins\Property::NewInstance('host')->SetLabel('Database Host')
				->SetDefaultValue('localhost'),
			\RainLoop\Plugins\Property::NewInstance('port')->SetLabel('Databse Port')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::INT)
				->SetDefaultValue(3306),
			\RainLoop\Plugins\Property::NewInstance('database')->SetLabel('Database Name')
				->SetDefaultValue('postfixadmin'),
			\RainLoop\Plugins\Property::NewInstance('table')->SetLabel('Table Name')
				->SetDefaultValue('mailbox'),
			\RainLoop\Plugins\Property::NewInstance('usercol')->SetLabel('Username column')
				->SetDefaultValue('username'),
			\RainLoop\Plugins\Property::NewInstance('passcol')->SetLabel('Password column')
				->SetDefaultValue('password'),
			\RainLoop\Plugins\Property::NewInstance('user')->SetLabel('Database User')
				->SetDefaultValue('postfixadmin'),
			\RainLoop\Plugins\Property::NewInstance('password')->SetLabel('Database Password')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::PASSWORD)
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance('encrypt')->SetLabel('Encrypt')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::SELECTION)
				->SetDefaultValue(array('Plain', 'Crypt', 'PLAIN-MD5', 'MD5-CRYPT', 'SHA256', 'SSHA256', 'SHA256-CRYPT', 'SHA512', 'SSHA512', 'SHA512-CRYPT', 'BLF-CRYPT'))
				->SetDescription('How should new passwords be encrypted?'),
			\RainLoop\Plugins\Property::NewInstance('allowed_emails')->SetLabel('Allowed Emails')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING_TEXT)
				->SetDescription('Space-delimited, wildcards supported; e.g.: user1@domain1.net user2@domain1.net *@domain2.net')
				->SetDefaultValue('*')
		);
	}
}
