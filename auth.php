<?php
if(!defined('DOKU_INC')) die();

/**
 * authenticate users using pwauth
 *
 * @license   MIT License (http://opensource.org/licenses/MIT)
 * @author    Che-Huai Lin <lzh9102@gmail.com>
 */
class auth_plugin_authpwauth extends DokuWiki_Auth_Plugin {
	private $pwauth_path;

	public function __construct() {
		parent::__construct();

		// check pwauth executable
		$this->pwauth_path = $this->getConf('pwauth_path');
		if (is_executable($this->pwauth_path)) {
			$this->cando['addUser']      = false;
			$this->cando['delUser']      = false;
			$this->cando['modLogin']     = false;
			$this->cando['modPass']      = false;
			$this->cando['modName']      = false;
			$this->cando['modMail']      = false;
			$this->cando['modGroups']    = false;
			$this->cando['getUsers']     = false;
			$this->cando['getUserCount'] = false;
			$this->cando['getGroups']    = false;
			$this->cando['external']     = false;
			$this->cando['logout']       = true;
			$this->success = true;
		} else {
			$this->success = false;
			echo "pwauth not found!";
		}

	}

	/**
	 * Check username/password
	 *
	 * @return bool
	 */
	public function checkPass($user, $pass) {
		// get user information
		$userinfo = posix_getpwnam($user);
		if (empty($userinfo)) {
			return false;
		}

		// run pwauth
		$handle = popen($this->pwauth_path, "w");
		if ($handle === false) {
			echo "failed to execute " . $this->pwauth_path . "!";
			return false;
		}

		// write user and password to pwauth
		if (fwrite($handle, "$user\n$pass\n") === false) {
			echo "failed to write to pwauth!";
			return false;
		}

		// authentication is successful only if the exit status of pwauth is 0
		$status = pclose($handle);
		if ($status == 0) {
			return true;
		}

		return false;
	}


	/**
	 * Return user info
	 *
	 * name string  full name of the user
	 * mail string  email addres of the user
	 * grps array   list of groups the user is in
	 *
	 * @param   string $user the user name
	 * @return  array containing user data or false
	 */
	public function getUserData($user) {
		$name = $this->getUserFullName($user);
		$mail = $this->getUserMail($user);
		$grps = $this->getUserGroups($user);
		return array("name" => $name, "mail" => $mail, "grps" => $grps);
	}

	private function getUserFullName($user) {
		$userinfo = posix_getpwnam($user);
		if ($userinfo === false) {
			return $user; // cannot find user info, use login name as name
		}
		// gecos is a comma separated list
		// the first fields (0) is the user's full name
		$gecos = $userinfo["gecos"];
		$fields = explode(",", $gecos);
		$name = $fields[0];
		// if the name is empty, use login name
		if ($name == "") {
			$name = $user;
		}
		return $name;
	}

	public function logOff(){
		// do nothing
	}

	/* List all available groups for a user
	 *
	 * @param string $user loginname
	 * @return array|bool false or array with all groups of this user.
	 */
	private function getUserGroups($user){
		// check if the user exists
		if (posix_getpwnam($user) === false) {
			return false;
		}
		// use the command "groups <user>" to find the groups
		// the format of output is as follows:
		// <user> : <group1> <group2> <group3> ...
		$output = shell_exec("groups " . escapeshellarg($user));
		$fields = explode(" ", $output);
		// fields[0] = <user>, field[1] = ':', field[2] = <group1>, ...
		// strip fields[0] and fields[1] to get the group array
		if (count($fields) < 2) { // error
			return false;
		}
		$groups = array_slice($fields, 2);
		return $groups;
	}

	private function getUserMail($user){
		return false;
	}
}
?>
