<?php
if(!defined('DOKU_INC')) die();

/**
 * authenticate users using pwauth
 *
 * @license   MIT License (http://opensource.org/licenses/MIT)
 * @author    Che-Huai Lin <lzh9102@gmail.com>
 * @author    Jamil Navarro <jamilnavarro@gmail.com>
 */
class auth_plugin_authpwauth extends DokuWiki_Auth_Plugin {
	private $pwauth_path;
	private $passwd_path;

	public function __construct() {
		parent::__construct();

		// check pwauth executable
		$this->pwauth_path = $this->getConf('pwauth_path');
		$this->passwd_path = $this->getConf('passwd_path');
		if (is_executable($this->pwauth_path)) {
			$this->cando['addUser']      = false;
			$this->cando['delUser']      = false;
			$this->cando['modLogin']     = false;
			$this->cando['modPass']      = false;
			$this->cando['modName']      = false;
			$this->cando['modMail']      = false;
			$this->cando['modGroups']    = false;
			
			if (is_readable($this->passwd_path)) {
				$this->cando['getUsers']     = true;
				$this->cando['getUserCount'] = true;
			} else {
				$this->cando['getUsers']     = false;
				$this->cando['getUserCount'] = false;
			}
			
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

	/**
	 * Return a count of the number of user which meet $filter criteria
	 *
	 * @author  Jamil Navarro <jamilnavarro@gmail.com>
	 *
	 * @param   array $filter
	 * @return  int
	 */
	public function getUserCount($filter = array()) {
		
		$handle = fopen($this->passwd_path, "r");
		$count = 0;
		if ($handle) {
			
			while (($line = fgets($handle)) !== false) {
				list($user,$x,$uid,$gid,$GECOS,$home,$shell) = explode(":",trim($line));
				// Skip root and service users
				if (in_array( $shell, array( "/bin/false", "/usr/sbin/nologin", "/bin/sync")) || $user == "root") {
					continue;
				}
				
				$info = $this->getUserData($user);
				if($this->_applyFilter($user, $info, $filter)) {
					$count++;
				}
			}
		}
		fclose($handle);
		return $count;
	}

	/*
	 * Bulk retrieval of user data
	 *
	 * @author  Jamil Navarro <jamilnavarro@gmail.com>
	 *
	 * @param   int     $start      index of first user to be returned
	 * @param   int     $limit      max number of users to be returned, 0 for unlimited
	 * @param   array   $filter     array of field/pattern pairs, null for no filter
	 * @return  array   list of userinfo (refer getUserData for internal userinfo details)
	 */
	public function retrieveUsers($start = 0, $limit = 0, $filter = array()) {
		
		$handle = fopen($this->passwd_path, "r");
		
		//return false on bad params
		if ( $start < 0 || $limit < 0 ) {
			return false;
		}
		
		$out = array();
		if ($handle) {
			$i = 0;
			$count = 0;
			
			while (($line = fgets($handle)) !== false) {
				list($user,$x,$uid,$gid,$GECOS,$home,$shell) = explode(":",trim($line));
				// Skip root and service users
				if (in_array( $shell, array( "/bin/false", "/usr/sbin/nologin", "/bin/sync")) || $user == "root") {
					continue;
				}
				
				$info = $this->getUserData($user);
				if($this->_applyFilter($user, $info, $filter)) {
					if($i >= $start) {
						$out[$user] = $info;
						$count++;
						if(($limit > 0) && ($count >= $limit)) break;
					}
					$i++;
				}
				
			}
		} 
		fclose($handle);
		return $out;
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
		$output = trim($output); //get rid of newline
		
		// userstring = <user>, groupstring = <group1> <group2> <group3> ...
		list($userstring,$groupstring) = explode( ":", $output);
		
		//groups[0] = <group1>, groups[1] = <group2>, groups[2] = <group3>...
		$groups = explode(" ",trim($groupstring)); //remove leading space from $groupstring, then split
		
		return $groups;
	}

	private function getUserMail($user){
		return false;
	}

	/**
	 * return true if $user + $info match $filter criteria, false otherwise
	 *
	 * @author  Jamil Navarro <jamilnavarro@gmail.com>
	 *
	 * @param   string $user User login
	 * @param   array  $info User's userinfo array
	 * @return  bool
	 */
	function _applyFilter($user, $info, $filter) {
		foreach($filter as $key => $pattern) {
			//sanitize pattern for use as regex
			$pattern = '/'.str_replace('/', '\/', $pattern).'/i';
			
			if($key == 'user') {
				if(!preg_match($pattern, $user)) return false;
			} else if($key == 'grps') {
				if(!count(preg_grep($pattern, $info['grps']))) { 
					return false;
				}
			} else {
				if(!preg_match($pattern, $info[$key])) {
					return false;
				}
			}
		}
		return true;
	}
}
?>
